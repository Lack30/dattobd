# dattobd relayfs 改造详细方案

## 一、改造概述

将磁盘写操作数据从写入 COW 文件改为通过 relayfs 传输到用户态进程。

### 核心改动点

| 文件 | 改动类型 | 说明 |
|------|----------|------|
| `src/relay_channel.c` | **新增** | relayfs 通道管理 |
| `src/relay_channel.h` | **新增** | relayfs 接口定义 |
| `src/tracer.c` | **修改** | BIO 拦截后写入 relayfs |
| `src/snap_device.h` | **修改** | 新增 relayfs 相关字段 |
| `src/dattobd.h` | **修改** | 新增消息类型和数据结构 |
| `src/netlink_handlers.c` | **修改** | 新增控制消息处理 |
| `src/Makefile` | **修改** | 添加新文件编译 |
| `app/dattobd-proxy.c` | **新增** | 用户态代理进程 |

---

## 二、内核模块改造

### 2.1 新增 relay_channel.h

```c
// src/relay_channel.h
#ifndef RELAY_CHANNEL_H_
#define RELAY_CHANNEL_H_

#include <linux/relay.h>
#include <linux/types.h>

#define RELAY_CHANNEL_NAME "dattobd_data"
#define RELAY_SUBBUF_SIZE (256 * 1024)    // 256KB 子缓冲区
#define RELAY_N_SUBBUFS   8               // 8 个子缓冲区

// 数据事件头
struct block_change_event {
    uint64_t block_addr;        // 块地址 (块号)
    uint64_t timestamp;         // 时间戳 (纳秒)
    uint32_t data_len;          // 数据长度
    uint32_t seq_num;           // 序列号
    uint8_t  operation;         // 操作类型: 0=写
    uint8_t  reserved[7];       // 保留
    // uint8_t data[];         // 变长数据 (紧随其后)
};

struct relay_channel_ctx {
    struct rchan *chan;         // relayfs 通道
    struct dentry *dir;         // debugfs 目录
    atomic64_t seq_counter;     // 序列号计数器
    unsigned int minor;         // 关联的设备 minor 号
    bool enabled;               // 是否启用
};

// 接口函数
int relay_channel_init(unsigned int minor);
void relay_channel_destroy(unsigned int minor);
int relay_channel_write(unsigned int minor, uint64_t block_addr, 
                        const void *data, uint32_t data_len);
bool relay_channel_is_enabled(unsigned int minor);

// 全局数组
extern struct relay_channel_ctx *relay_channels;

#endif // RELAY_CHANNEL_H_
```

### 2.2 新增 relay_channel.c

```c
// src/relay_channel.c
#include "relay_channel.h"
#include "logging.h"
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/ktime.h>

#define MAX_RELAY_CHANNELS 256

struct relay_channel_ctx *relay_channels[MAX_RELAY_CHANNELS];
static struct dentry *relay_root_dir;

static int relay_subbuf_start_callback(struct rchan_buf *buf, void *subbuf,
                                       void *prev_subbuf, size_t prev_padding)
{
    return 1; // 允许覆盖
}

static void relay_buf_unmapped_callback(struct rchan_buf *buf,
                                        struct file *filp)
{
    // 用户态关闭了文件
}

static struct dentry *relay_create_buf_file_callback(const char *filename,
                                                     struct dentry *parent,
                                                     umode_t mode,
                                                     struct rchan_buf *buf,
                                                     int *is_global)
{
    return debugfs_create_file(filename, mode, parent, buf,
                               &relay_file_operations);
}

static struct rchan_callbacks relay_callbacks = {
    .subbuf_start = relay_subbuf_start_callback,
    .buf_unmapped = relay_buf_unmapped_callback,
    .create_buf_file = relay_create_buf_file_callback,
};

int __init relay_channel_global_init(void)
{
    relay_root_dir = debugfs_create_dir("dattobd", NULL);
    if (!relay_root_dir) {
        LOG_ERROR(-ENOMEM, "failed to create debugfs directory");
        return -ENOMEM;
    }
    return 0;
}

void relay_channel_global_cleanup(void)
{
    int i;
    for (i = 0; i < MAX_RELAY_CHANNELS; i++) {
        if (relay_channels[i])
            relay_channel_destroy(i);
    }
    debugfs_remove(relay_root_dir);
}

int relay_channel_init(unsigned int minor)
{
    struct relay_channel_ctx *ctx;
    char chan_name[32];

    if (minor >= MAX_RELAY_CHANNELS)
        return -EINVAL;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    snprintf(chan_name, sizeof(chan_name), "dev%d", minor);

    ctx->chan = relay_open(chan_name, relay_root_dir,
                           RELAY_SUBBUF_SIZE, RELAY_N_SUBBUFS,
                           &relay_callbacks, NULL);
    if (!ctx->chan) {
        kfree(ctx);
        return -ENOMEM;
    }

    atomic64_set(&ctx->seq_counter, 0);
    ctx->minor = minor;
    ctx->enabled = true;

    relay_channels[minor] = ctx;
    return 0;
}

void relay_channel_destroy(unsigned int minor)
{
    struct relay_channel_ctx *ctx;

    if (minor >= MAX_RELAY_CHANNELS)
        return;

    ctx = relay_channels[minor];
    if (!ctx)
        return;

    ctx->enabled = false;
    relay_close(ctx->chan);
    kfree(ctx);
    relay_channels[minor] = NULL;
}

int relay_channel_write(unsigned int minor, uint64_t block_addr,
                        const void *data, uint32_t data_len)
{
    struct relay_channel_ctx *ctx;
    struct block_change_event event;
    size_t total_len;

    if (minor >= MAX_RELAY_CHANNELS)
        return -EINVAL;

    ctx = relay_channels[minor];
    if (!ctx || !ctx->enabled)
        return -ENODEV;

    // 构造事件头
    event.block_addr = block_addr;
    event.timestamp = ktime_get_real_ns();
    event.data_len = data_len;
    event.seq_num = atomic64_inc_return(&ctx->seq_counter);
    event.operation = 0; // 写操作
    memset(event.reserved, 0, sizeof(event.reserved));

    total_len = sizeof(event) + data_len;

    // 写入 relayfs
    relay_write(ctx->chan, &event, sizeof(event));
    relay_write(ctx->chan, data, data_len);

    return 0;
}

bool relay_channel_is_enabled(unsigned int minor)
{
    if (minor >= MAX_RELAY_CHANNELS)
        return false;
    return relay_channels[minor] && relay_channels[minor]->enabled;
}
```

### 2.3 修改 snap_device.h

在 `struct snap_device` 中新增字段：

```c
// 在 struct snap_device 中添加
struct snap_device {
    // ... 现有字段 ...
    
    // relayfs 相关字段 (新增)
    struct relay_channel_ctx *sd_relay_chan;  // relayfs 通道上下文
    bool sd_relay_mode;                        // 是否使用 relayfs 模式
};
```

### 2.4 修改 dattobd.h

新增消息类型和数据结构：

```c
// 新增消息类型
#define MSG_START_RELAY    20   // 启动 relayfs 数据流
#define MSG_STOP_RELAY     21   // 停止 relayfs 数据流
#define MSG_RELAY_STATUS   22   // 获取 relayfs 状态

// relayfs 配置参数
struct relay_config_params {
    unsigned int minor;           // 设备 minor 号
    unsigned long subbuf_size;    // 子缓冲区大小
    unsigned int n_subbufs;       // 子缓冲区数量
};

// relayfs 状态信息
struct relay_status_info {
    unsigned int minor;
    bool enabled;
    uint64_t events_sent;
    uint64_t bytes_sent;
    uint32_t overflows;
};
```

### 2.5 修改 tracer.c

#### 2.5.1 修改 snap_trace_bio() 函数

```c
// 在 tracer.c 中修改 snap_trace_bio()
static int snap_trace_bio(struct snap_device *dev, struct bio *bio)
{
    int ret;
    struct bio *new_bio = NULL;
    struct tracing_params *tp = NULL;
    sector_t start_sect, end_sect;
    unsigned int bytes, pages;

    // 检查是否需要 COW
    if (!bio_needs_cow(bio, dev->sd_cow_inode) || tracer_read_fail_state(dev)) {
        return SUBMIT_BIO_REAL(dev, bio);
    }

    // === 新增: relayfs 模式处理 ===
    if (dev->sd_relay_mode && relay_channel_is_enabled(dev->sd_minor)) {
        return snap_trace_bio_relay(dev, bio);
    }
    // === relayfs 模式处理结束 ===

    // 原有 COW 模式处理逻辑...
    // (保持原有代码不变)
}

// 新增: relayfs 模式的 BIO 处理函数
static int snap_trace_bio_relay(struct snap_device *dev, struct bio *bio)
{
    sector_t start_sect, end_sect;
    void *data_buf;
    struct bio_vec bvec;
    struct bvec_iter iter;
    size_t offset = 0;
    int ret = 0;

    start_sect = ROUND_DOWN(bio_sector(bio) - dev->sd_sect_off, SECTORS_PER_BLOCK) 
                 + dev->sd_sect_off;
    end_sect = ROUND_UP(bio_sector(bio) + (bio_size(bio) / SECTOR_SIZE) - dev->sd_sect_off,
                        SECTORS_PER_BLOCK) + dev->sd_sect_off;

    // 分配临时缓冲区
    data_buf = kmalloc(COW_BLOCK_SIZE, GFP_NOIO);
    if (!data_buf) {
        LOG_ERROR(-ENOMEM, "failed to allocate relay buffer");
        return SUBMIT_BIO_REAL(dev, bio);
    }

    // 从 bio 中复制数据
    bio_for_each_segment(bvec, bio, iter) {
        void *page_addr = kmap_atomic(bvec.bv_page);
        memcpy(data_buf + offset, page_addr + bvec.bv_offset, bvec.bv_len);
        kunmap_atomic(page_addr);
        offset += bvec.bv_len;
    }

    // 写入 relayfs
    ret = relay_channel_write(dev->sd_minor, 
                               start_sect / SECTORS_PER_BLOCK,
                               data_buf, COW_BLOCK_SIZE);

    kfree(data_buf);

    if (ret) {
        LOG_ERROR(ret, "failed to write to relay channel");
    }

    // 放行原始 BIO
    return SUBMIT_BIO_REAL(dev, bio);
}
```

#### 2.5.2 修改 inc_trace_bio() 函数

```c
static int inc_trace_bio(struct snap_device *dev, struct bio *bio)
{
    int ret = 0;
    
    // === 新增: relayfs 模式处理 ===
    if (dev->sd_relay_mode && relay_channel_is_enabled(dev->sd_minor)) {
        return inc_trace_bio_relay(dev, bio);
    }
    // === relayfs 模式处理结束 ===

    // 原有增量模式处理逻辑...
}

// 新增: relayfs 模式的增量追踪
static int inc_trace_bio_relay(struct snap_device *dev, struct bio *bio)
{
    sector_t start_sect, end_sect;
    
    start_sect = bio_sector(bio);
    end_sect = start_sect + (bio_size(bio) / SECTOR_SIZE);

    // 只记录变更块位置，不传输数据
    relay_channel_write_meta(dev->sd_minor, start_sect, end_sect - start_sect);

    // 放行原始 BIO
    SUBMIT_BIO_REAL(dev, bio);
    return 0;
}
```

### 2.6 修改 netlink_handlers.c

新增 relayfs 控制消息处理：

```c
// 在 netlink_handlers.c 中添加

#include "relay_channel.h"

static int handle_start_relay(unsigned int minor, struct relay_config_params *params)
{
    int ret;
    struct snap_device *dev;
    snap_device_array snap_devices = get_snap_device_array();

    ret = verify_minor_in_use(minor, snap_devices);
    if (ret)
        goto out;

    dev = snap_devices[minor];

    // 初始化 relayfs 通道
    ret = relay_channel_init(minor);
    if (ret)
        goto out;

    dev->sd_relay_mode = true;
    dev->sd_relay_chan = relay_channels[minor];

    LOG_DEBUG("relay mode enabled for minor %u", minor);

out:
    put_snap_device_array(snap_devices);
    return ret;
}

static int handle_stop_relay(unsigned int minor)
{
    struct snap_device *dev;
    snap_device_array snap_devices = get_snap_device_array();

    if (verify_minor_in_use(minor, snap_devices))
        goto out;

    dev = snap_devices[minor];
    dev->sd_relay_mode = false;

    relay_channel_destroy(minor);
    dev->sd_relay_chan = NULL;

    LOG_DEBUG("relay mode disabled for minor %u", minor);

out:
    put_snap_device_array(snap_devices);
    return 0;
}

// 在 handle_request() 中添加新消息处理
static int handle_request(struct sk_buff *skb, struct genl_info *info)
{
    // ... 现有代码 ...

    switch (msg_type) {
    // ... 现有 case ...
    
    case MSG_START_RELAY:
        ret = handle_start_relay(params.minor, &relay_params);
        break;
        
    case MSG_STOP_RELAY:
        ret = handle_stop_relay(params.minor);
        break;
        
    case MSG_RELAY_STATUS:
        ret = handle_relay_status(params.minor, &status);
        break;
    }
    
    // ...
}
```

### 2.7 修改 Makefile

```makefile
# 在 src/Makefile 中添加
dattobd-objs += relay_channel.o
```

---

## 三、用户态进程开发

### 3.1 dattobd-proxy.c

```c
// app/dattobd-proxy.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#define RELAY_PATH "/sys/kernel/debug/dattobd/dev%d"
#define BLOCK_SIZE 4096

struct block_change_event {
    uint64_t block_addr;
    uint64_t timestamp;
    uint32_t data_len;
    uint32_t seq_num;
    uint8_t  operation;
    uint8_t  reserved[7];
};

static volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
}

void *receiver_thread(void *arg) {
    int minor = *(int *)arg;
    char relay_path[256];
    int fd;
    struct pollfd pfd;
    struct block_change_event event;
    void *data_buf;
    ssize_t n;

    snprintf(relay_path, sizeof(relay_path), RELAY_PATH, minor);
    
    fd = open(relay_path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        perror("open relay");
        return NULL;
    }

    data_buf = malloc(BLOCK_SIZE);
    if (!data_buf) {
        close(fd);
        return NULL;
    }

    pfd.fd = fd;
    pfd.events = POLLIN;

    printf("Listening on %s\n", relay_path);

    while (running) {
        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }
        if (ret == 0)
            continue;

        // 读取事件头
        n = read(fd, &event, sizeof(event));
        if (n != sizeof(event)) {
            continue;
        }

        // 读取数据
        if (event.data_len > 0 && event.data_len <= BLOCK_SIZE) {
            n = read(fd, data_buf, event.data_len);
            if (n != event.data_len) {
                continue;
            }
        }

        // 处理数据 (这里可以写入文件或发送到网络)
        printf("Block %lu changed, seq=%u, len=%u\n",
               (unsigned long)event.block_addr, event.seq_num, event.data_len);

        // 示例: 写入本地文件
        // write_block_to_file(event.block_addr, data_buf, event.data_len);
    }

    free(data_buf);
    close(fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    int minor = 0;
    pthread_t tid;

    if (argc > 1) {
        minor = atoi(argv[1]);
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 创建接收线程
    pthread_create(&tid, NULL, receiver_thread, &minor);

    // 等待退出
    pthread_join(tid, NULL);

    printf("Proxy stopped\n");
    return 0;
}
```

### 3.2 用户态 Makefile

```makefile
# app/Makefile
CC = gcc
CFLAGS = -Wall -O2 -pthread

all: dattobd-proxy

dattobd-proxy: dattobd-proxy.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f dattobd-proxy

install: dattobd-proxy
	install -m 755 dattobd-proxy /usr/local/bin/
```

---

## 四、编译和测试

### 4.1 编译内核模块

```bash
cd /root/c/dattobd
make clean
make
```

### 4.2 加载模块

```bash
sudo insmod src/dattobd.ko
```

### 4.3 挂载 debugfs

```bash
sudo mount -t debugfs none /sys/kernel/debug
```

### 4.4 启动快照

```bash
# 创建快照 (传统模式)
sudo dbdctl setup-snapshot /dev/sda1 /.datto 0

# 启用 relayfs 模式
# (需要通过 Netlink 发送 MSG_START_RELAY 消息)
```

### 4.5 启动用户态代理

```bash
sudo ./app/dattobd-proxy 0
```

---

## 五、数据流图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              内核空间                                        │
│                                                                             │
│  ┌─────────────┐      ┌─────────────────┐      ┌─────────────────────────┐ │
│  │ 应用程序    │      │ tracer.c        │      │ relay_channel.c         │ │
│  │ 写请求      │ ───► │ snap_trace_bio()│ ───► │ relay_channel_write()   │ │
│  └─────────────┘      │ 或              │      │                         │ │
│                       │ inc_trace_bio() │      └───────────┬─────────────┘ │
│                       └─────────────────┘                  │               │
│                                                            │               │
│                                                            ▼               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        relayfs                                       │   │
│  │  /sys/kernel/debug/dattobd/dev0                                     │   │
│  │  ┌───────────────────────────────────────────────────────────────┐  │   │
│  │  │  Ring Buffer (per-CPU)                                        │  │   │
│  │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐            │  │   │
│  │  │  │ Subbuf0 │ │ Subbuf1 │ │ Subbuf2 │ │ Subbuf3 │ ...        │  │   │
│  │  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘            │  │   │
│  │  └───────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ read()
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              用户空间                                        │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        dattobd-proxy                                 │   │
│  │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐ │   │
│  │  │ 接收线程         │    │ 处理线程         │    │ 存储线程        │ │   │
│  │  │ poll() + read() │───►│ 解析事件头       │───►│ 写入本地文件    │ │   │
│  │  │                 │    │ 提取数据         │    │ 或网络传输      │ │   │
│  │  └─────────────────┘    └─────────────────┘    └─────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 六、性能优化建议

### 6.1 批量写入

```c
// 在内核中批量收集数据，减少 relay_write 调用次数
#define BATCH_SIZE 16

struct batch_buffer {
    struct block_change_event events[BATCH_SIZE];
    void *data[BATCH_SIZE];
    int count;
    spinlock_t lock;
};

int relay_channel_write_batch(unsigned int minor, struct batch_buffer *batch)
{
    int i;
    struct relay_channel_ctx *ctx = relay_channels[minor];
    
    for (i = 0; i < batch->count; i++) {
        relay_write(ctx->chan, &batch->events[i], sizeof(batch->events[i]));
        relay_write(ctx->chan, batch->data[i], batch->events[i].data_len);
    }
    
    batch->count = 0;
    return 0;
}
```

### 6.2 用户态多线程读取

```c
// 每个 CPU 一个读取线程
void *receiver_thread_per_cpu(void *arg) {
    int cpu = *(int *)arg;
    char relay_path[256];
    
    snprintf(relay_path, sizeof(relay_path), 
             "/sys/kernel/debug/dattobd/dev%d/cpu%d", minor, cpu);
    
    // ... 读取逻辑 ...
}
```

---

## 七、风险与对策

| 风险 | 影响 | 对策 |
|------|------|------|
| debugfs 未挂载 | relayfs 不可用 | 自动挂载或提示用户 |
| 缓冲区溢出 | 数据丢失 | 增大缓冲区、多级缓冲 |
| 用户态进程崩溃 | 数据丢失 | 内核侧临时缓存、进程监控重启 |
| 高频写入性能 | 延迟增加 | 批量写入、多线程处理 |

---

## 八、后续扩展

1. **网络传输**: 将数据发送到远程服务器
2. **压缩加密**: 在用户态对数据进行压缩/加密
3. **断点续传**: 支持进程重启后继续传输
4. **多设备支持**: 同时监控多个块设备
