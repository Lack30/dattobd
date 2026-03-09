# relayfs 改造详细实施步骤

## 一、文件结构变更

### 新增文件

```
src/
├── relay_channel.c          # relayfs 通道管理实现
├── relay_channel.h          # relayfs 接口定义
app/
├── dattobd-proxy.c          # 用户态代理进程
├── Makefile                 # 用户态编译脚本
```

### 修改文件

```
src/
├── dattobd.h                # 新增消息类型
├── snap_device.h            # 新增 relayfs 相关字段
├── tracer.c                 # 修改 BIO 处理逻辑
├── netlink_handlers.c       # 新增控制消息处理
├── module_control.c         # 初始化/清理 relayfs
├── Makefile                 # 添加新文件编译
```

---

## 二、分步实施

### 步骤 1: 创建 relay_channel.h

```c
// src/relay_channel.h
// SPDX-License-Identifier: GPL-2.0-only

#ifndef RELAY_CHANNEL_H_
#define RELAY_CHANNEL_H_

#include <linux/relay.h>
#include <linux/types.h>
#include <linux/ktime.h>

#define RELAY_SUBBUF_SIZE_DEFAULT    (256 * 1024)
#define RELAY_N_SUBBUFS_DEFAULT      8
#define RELAY_MAX_CHANNELS           256

struct block_change_event {
    uint64_t block_addr;
    uint64_t timestamp;
    uint32_t data_len;
    uint32_t seq_num;
    uint8_t  operation;
    uint8_t  reserved[7];
};

struct relay_channel_ctx {
    struct rchan *chan;
    atomic64_t seq_counter;
    atomic64_t bytes_sent;
    atomic64_t events_sent;
    unsigned int minor;
    bool enabled;
    struct mutex config_lock;
};

int relay_channel_global_init(void);
void relay_channel_global_cleanup(void);

int relay_channel_create(unsigned int minor, unsigned long subbuf_size, unsigned int n_subbufs);
void relay_channel_destroy(unsigned int minor);

int relay_channel_write_data(unsigned int minor, uint64_t block_addr,
                             const void *data, uint32_t data_len);
int relay_channel_write_meta(unsigned int minor, uint64_t block_addr, uint32_t len);

bool relay_channel_is_enabled(unsigned int minor);
int relay_channel_get_status(unsigned int minor, uint64_t *events, uint64_t *bytes);

#endif
```

### 步骤 2: 创建 relay_channel.c

```c
// src/relay_channel.c
// SPDX-License-Identifier: GPL-2.0-only

#include "relay_channel.h"
#include "logging.h"
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/delay.h>

static struct dentry *relay_root_dir;
static struct relay_channel_ctx *relay_channels[RELAY_MAX_CHANNELS];
static DEFINE_MUTEX(relay_global_lock);

static int relay_subbuf_start(struct rchan_buf *buf, void *subbuf,
                              void *prev_subbuf, size_t prev_padding)
{
    return 1;
}

static struct dentry *relay_create_buf_file(const char *filename,
                                            struct dentry *parent,
                                            umode_t mode,
                                            struct rchan_buf *buf,
                                            int *is_global)
{
    return debugfs_create_file(filename, mode, parent, buf,
                               &relay_file_operations);
}

static struct rchan_callbacks relay_cb = {
    .subbuf_start = relay_subbuf_start,
    .create_buf_file = relay_create_buf_file,
};

int __init relay_channel_global_init(void)
{
    mutex_lock(&relay_global_lock);
    relay_root_dir = debugfs_create_dir("dattobd", NULL);
    if (IS_ERR_OR_NULL(relay_root_dir)) {
        mutex_unlock(&relay_global_lock);
        LOG_ERROR(-ENOMEM, "failed to create debugfs dir");
        return -ENOMEM;
    }
    mutex_unlock(&relay_global_lock);
    return 0;
}

void relay_channel_global_cleanup(void)
{
    int i;
    mutex_lock(&relay_global_lock);
    for (i = 0; i < RELAY_MAX_CHANNELS; i++) {
        if (relay_channels[i])
            relay_channel_destroy(i);
    }
    debugfs_remove(relay_root_dir);
    relay_root_dir = NULL;
    mutex_unlock(&relay_global_lock);
}

int relay_channel_create(unsigned int minor, unsigned long subbuf_size, unsigned int n_subbufs)
{
    struct relay_channel_ctx *ctx;
    char name[32];
    int ret = 0;

    if (minor >= RELAY_MAX_CHANNELS)
        return -EINVAL;

    mutex_lock(&relay_global_lock);

    if (relay_channels[minor]) {
        ret = -EEXIST;
        goto out;
    }

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) {
        ret = -ENOMEM;
        goto out;
    }

    snprintf(name, sizeof(name), "dev%u", minor);

    ctx->chan = relay_open(name, relay_root_dir, subbuf_size, n_subbufs, &relay_cb, NULL);
    if (!ctx->chan) {
        kfree(ctx);
        ret = -ENOMEM;
        goto out;
    }

    atomic64_set(&ctx->seq_counter, 0);
    atomic64_set(&ctx->bytes_sent, 0);
    atomic64_set(&ctx->events_sent, 0);
    ctx->minor = minor;
    ctx->enabled = true;
    mutex_init(&ctx->config_lock);

    relay_channels[minor] = ctx;

out:
    mutex_unlock(&relay_global_lock);
    return ret;
}

void relay_channel_destroy(unsigned int minor)
{
    struct relay_channel_ctx *ctx;

    if (minor >= RELAY_MAX_CHANNELS)
        return;

    mutex_lock(&relay_global_lock);
    ctx = relay_channels[minor];
    if (!ctx)
        goto out;

    ctx->enabled = false;
    msleep(100);
    relay_close(ctx->chan);
    kfree(ctx);
    relay_channels[minor] = NULL;

out:
    mutex_unlock(&relay_global_lock);
}

int relay_channel_write_data(unsigned int minor, uint64_t block_addr,
                             const void *data, uint32_t data_len)
{
    struct relay_channel_ctx *ctx;
    struct block_change_event event;
    size_t total;

    if (minor >= RELAY_MAX_CHANNELS)
        return -EINVAL;

    ctx = relay_channels[minor];
    if (!ctx || !ctx->enabled)
        return -ENODEV;

    event.block_addr = block_addr;
    event.timestamp = ktime_get_real_ns();
    event.data_len = data_len;
    event.seq_num = atomic64_inc_return(&ctx->seq_counter);
    event.operation = 0;
    memset(event.reserved, 0, sizeof(event.reserved));

    total = sizeof(event) + data_len;

    relay_write(ctx->chan, &event, sizeof(event));
    if (data && data_len > 0)
        relay_write(ctx->chan, data, data_len);

    atomic64_add(total, &ctx->bytes_sent);
    atomic64_inc(&ctx->events_sent);

    return 0;
}

int relay_channel_write_meta(unsigned int minor, uint64_t block_addr, uint32_t len)
{
    struct relay_channel_ctx *ctx;
    struct block_change_event event;

    if (minor >= RELAY_MAX_CHANNELS)
        return -EINVAL;

    ctx = relay_channels[minor];
    if (!ctx || !ctx->enabled)
        return -ENODEV;

    event.block_addr = block_addr;
    event.timestamp = ktime_get_real_ns();
    event.data_len = len;
    event.seq_num = atomic64_inc_return(&ctx->seq_counter);
    event.operation = 1;  // metadata only
    memset(event.reserved, 0, sizeof(event.reserved));

    relay_write(ctx->chan, &event, sizeof(event));

    atomic64_add(sizeof(event), &ctx->bytes_sent);
    atomic64_inc(&ctx->events_sent);

    return 0;
}

bool relay_channel_is_enabled(unsigned int minor)
{
    if (minor >= RELAY_MAX_CHANNELS)
        return false;
    return relay_channels[minor] && relay_channels[minor]->enabled;
}

int relay_channel_get_status(unsigned int minor, uint64_t *events, uint64_t *bytes)
{
    struct relay_channel_ctx *ctx;

    if (minor >= RELAY_MAX_CHANNELS)
        return -EINVAL;

    ctx = relay_channels[minor];
    if (!ctx)
        return -ENODEV;

    *events = atomic64_read(&ctx->events_sent);
    *bytes = atomic64_read(&ctx->bytes_sent);

    return 0;
}
```

### 步骤 3: 修改 dattobd.h

在现有消息类型后添加：

```c
// 在现有消息类型后添加 (大约在 100 行附近)

// relayfs 消息类型
#define MSG_START_RELAY    20
#define MSG_STOP_RELAY     21
#define MSG_RELAY_STATUS   22

// relayfs 配置
struct relay_config {
    unsigned int minor;
    unsigned long subbuf_size;
    unsigned int n_subbufs;
};

// relayfs 状态
struct relay_status {
    unsigned int minor;
    bool enabled;
    uint64_t events_sent;
    uint64_t bytes_sent;
};
```

### 步骤 4: 修改 snap_device.h

在 `struct snap_device` 中添加字段：

```c
// 在 struct snap_device 定义中添加 (大约在 60-70 行附近)

struct snap_device {
    // ... 现有字段 ...
    
    // relayfs 模式字段
    bool sd_relay_mode;
    struct relay_channel_ctx *sd_relay_ctx;
};
```

### 步骤 5: 修改 tracer.c

#### 5.1 添加头文件

```c
// 在 tracer.c 开头添加
#include "relay_channel.h"
```

#### 5.2 修改 snap_trace_bio()

```c
// 在 snap_trace_bio() 函数开头添加 relayfs 模式检查
static int snap_trace_bio(struct snap_device *dev, struct bio *bio)
{
    int ret;
    struct bio *new_bio = NULL;
    struct tracing_params *tp = NULL;
    sector_t start_sect, end_sect;
    unsigned int bytes, pages;

    // === 新增: relayfs 模式 ===
    if (dev->sd_relay_mode && relay_channel_is_enabled(dev->sd_minor)) {
        return snap_trace_bio_relay(dev, bio);
    }
    // === relayfs 模式结束 ===

    // 原有代码...
}

// 新增函数
static int snap_trace_bio_relay(struct snap_device *dev, struct bio *bio)
{
    sector_t start_sect;
    void *data_buf;
    struct bio_vec bvec;
    struct bvec_iter iter;
    size_t offset = 0;
    int ret;

    if (!bio_needs_cow(bio, dev->sd_cow_inode)) {
        return SUBMIT_BIO_REAL(dev, bio);
    }

    start_sect = ROUND_DOWN(bio_sector(bio) - dev->sd_sect_off, SECTORS_PER_BLOCK)
                 + dev->sd_sect_off;

    data_buf = kmalloc(COW_BLOCK_SIZE, GFP_NOIO);
    if (!data_buf) {
        LOG_ERROR(-ENOMEM, "relay buffer alloc failed");
        return SUBMIT_BIO_REAL(dev, bio);
    }

    bio_for_each_segment(bvec, bio, iter) {
        void *addr = kmap_atomic(bvec.bv_page);
        memcpy(data_buf + offset, addr + bvec.bv_offset, bvec.bv_len);
        kunmap_atomic(addr);
        offset += bvec.bv_len;
    }

    ret = relay_channel_write_data(dev->sd_minor,
                                    start_sect / SECTORS_PER_BLOCK,
                                    data_buf, COW_BLOCK_SIZE);
    kfree(data_buf);

    if (ret)
        LOG_ERROR(ret, "relay write failed");

    return SUBMIT_BIO_REAL(dev, bio);
}
```

#### 5.3 修改 inc_trace_bio()

```c
static int inc_trace_bio(struct snap_device *dev, struct bio *bio)
{
    // === 新增: relayfs 模式 ===
    if (dev->sd_relay_mode && relay_channel_is_enabled(dev->sd_minor)) {
        return inc_trace_bio_relay(dev, bio);
    }
    // === relayfs 模式结束 ===

    // 原有代码...
}

static int inc_trace_bio_relay(struct snap_device *dev, struct bio *bio)
{
    sector_t start_sect = bio_sector(bio);
    uint32_t len = bio_size(bio) / SECTOR_SIZE;

    relay_channel_write_meta(dev->sd_minor, start_sect, len);

    SUBMIT_BIO_REAL(dev, bio);
    return 0;
}
```

### 步骤 6: 修改 netlink_handlers.c

```c
// 添加头文件
#include "relay_channel.h"

// 添加处理函数
static int handle_start_relay(struct genl_info *info)
{
    struct relay_config cfg = {0};
    struct snap_device *dev;
    int ret;

    ret = copy_from_user_relay_config(info, &cfg);
    if (ret)
        return ret;

    if (cfg.minor >= dattobd_max_snap_devices)
        return -EINVAL;

    snap_device_array snap_devices = get_snap_device_array_mut();
    dev = snap_devices[cfg.minor];
    if (!dev) {
        put_snap_device_array_mut(snap_devices);
        return -ENODEV;
    }

    if (!cfg.subbuf_size)
        cfg.subbuf_size = RELAY_SUBBUF_SIZE_DEFAULT;
    if (!cfg.n_subbufs)
        cfg.n_subbufs = RELAY_N_SUBBUFS_DEFAULT;

    ret = relay_channel_create(cfg.minor, cfg.subbuf_size, cfg.n_subbufs);
    if (ret) {
        put_snap_device_array_mut(snap_devices);
        return ret;
    }

    dev->sd_relay_mode = true;
    dev->sd_relay_ctx = relay_channels[cfg.minor];

    put_snap_device_array_mut(snap_devices);
    return 0;
}

static int handle_stop_relay(struct genl_info *info)
{
    unsigned int minor;
    struct snap_device *dev;
    int ret;

    ret = copy_from_user_minor(info, &minor);
    if (ret)
        return ret;

    snap_device_array snap_devices = get_snap_device_array_mut();
    dev = snap_devices[minor];
    if (!dev) {
        put_snap_device_array_mut(snap_devices);
        return -ENODEV;
    }

    dev->sd_relay_mode = false;
    dev->sd_relay_ctx = NULL;
    relay_channel_destroy(minor);

    put_snap_device_array_mut(snap_devices);
    return 0;
}

static int handle_relay_status(struct genl_info *info)
{
    unsigned int minor;
    struct relay_status status = {0};
    int ret;

    ret = copy_from_user_minor(info, &minor);
    if (ret)
        return ret;

    status.minor = minor;
    status.enabled = relay_channel_is_enabled(minor);
    relay_channel_get_status(minor, &status.events_sent, &status.bytes_sent);

    return send_relay_status_reply(info, &status);
}

// 在 handle_request() switch 中添加
case MSG_START_RELAY:
    return handle_start_relay(info);
case MSG_STOP_RELAY:
    return handle_stop_relay(info);
case MSG_RELAY_STATUS:
    return handle_relay_status(info);
```

### 步骤 7: 修改 module_control.c

```c
// 添加头文件
#include "relay_channel.h"

// 在 init 函数中添加
static int __init dattobd_init(void)
{
    int ret;

    // ... 现有初始化代码 ...

    ret = relay_channel_global_init();
    if (ret) {
        LOG_ERROR(ret, "relay channel init failed");
        goto error_relay;
    }

    // ... 继续初始化 ...

    return 0;

error_relay:
    // 清理已分配资源
    // ...
    return ret;
}

// 在 exit 函数中添加
static void __exit dattobd_exit(void)
{
    // ... 现有清理代码 ...

    relay_channel_global_cleanup();

    // ... 继续清理 ...
}
```

### 步骤 8: 修改 Makefile

```makefile
# 在现有 SRCS 行后添加
SRCS := $(notdir $(wildcard $M/*.c))

# 或者在 obj-y 中添加
dattobd-y += relay_channel.o
```

---

## 三、用户态程序

### dattobd-proxy.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#define RELAY_BASE_PATH "/sys/kernel/debug/dattobd"
#define BLOCK_SIZE 4096

struct block_change_event {
    uint64_t block_addr;
    uint64_t timestamp;
    uint32_t data_len;
    uint32_t seq_num;
    uint8_t  operation;
    uint8_t  reserved[7];
};

static volatile int g_running = 1;

void signal_handler(int sig) {
    g_running = 0;
}

int main(int argc, char *argv[]) {
    int minor = 0;
    char relay_path[256];
    int fd = -1;
    struct pollfd pfd;
    struct block_change_event event;
    void *data_buf = NULL;
    FILE *output = NULL;
    ssize_t n;

    if (argc > 1) {
        minor = atoi(argv[1]);
    }
    if (argc > 2) {
        output = fopen(argv[2], "wb");
        if (!output) {
            perror("fopen output");
            return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    snprintf(relay_path, sizeof(relay_path), "%s/dev%d", RELAY_BASE_PATH, minor);

    fd = open(relay_path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        perror("open relay");
        return 1;
    }

    data_buf = malloc(BLOCK_SIZE);
    if (!data_buf) {
        close(fd);
        return 1;
    }

    pfd.fd = fd;
    pfd.events = POLLIN;

    printf("Listening on %s (minor=%d)\n", relay_path, minor);
    printf("Press Ctrl+C to stop\n\n");

    while (g_running) {
        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }
        if (ret == 0)
            continue;

        n = read(fd, &event, sizeof(event));
        if (n != sizeof(event)) {
            if (n < 0 && errno != EAGAIN)
                perror("read event");
            continue;
        }

        printf("[%u] Block %lu, op=%d, len=%u\n",
               event.seq_num, (unsigned long)event.block_addr,
               event.operation, event.data_len);

        if (event.data_len > 0 && event.data_len <= BLOCK_SIZE) {
            n = read(fd, data_buf, event.data_len);
            if (n != event.data_len) {
                fprintf(stderr, "read data mismatch: %zd != %u\n", n, event.data_len);
                continue;
            }

            if (output && event.operation == 0) {
                fwrite(&event, sizeof(event), 1, output);
                fwrite(data_buf, 1, event.data_len, output);
                fflush(output);
            }
        }
    }

    printf("\nShutting down...\n");

    free(data_buf);
    close(fd);
    if (output)
        fclose(output);

    return 0;
}
```

---

## 四、编译和测试

### 4.1 编译

```bash
# 编译内核模块
cd /root/c/dattobd
make clean
make

# 编译用户态程序
cd app
make
```

### 4.2 测试流程

```bash
# 1. 挂载 debugfs
sudo mount -t debugfs none /sys/kernel/debug

# 2. 加载模块
sudo insmod src/dattobd.ko

# 3. 创建快照
sudo dbdctl setup-snapshot /dev/sda1 /.datto 0

# 4. 启动用户态代理 (需要先通过 Netlink 启用 relayfs)
sudo ./app/dattobd-proxy 0

# 5. 产生写操作
sudo dd if=/dev/urandom of=/testfile bs=4K count=10

# 6. 观察输出
# 用户态代理应该打印出变更块信息

# 7. 清理
sudo dbdctl destroy 0
sudo rmmod dattobd
```

---

## 五、注意事项

1. **debugfs 必须挂载**: relayfs 依赖 debugfs
2. **权限**: 用户态程序需要 root 权限访问 debugfs
3. **缓冲区溢出**: 高频写入可能导致数据丢失
4. **内核版本兼容**: relayfs API 在不同内核版本基本稳定
