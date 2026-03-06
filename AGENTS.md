# AGENTS.md - Datto Block Driver 项目指南

本文档为 AI 编程助手提供项目上下文和开发指南。

## 项目概述

**Datto Block Driver (dattobd)** 是一个 Linux 内核模块，用于实现块设备的实时快照和增量备份功能。它使用 Copy-on-Write (COW) 机制在块设备级别捕获数据变化。

- **类型**: Linux Kernel Module (LKM)
- **语言**: C (GNU89 标准)
- **许可证**: GPL-2.0-only
- **版本**: 0.12.0
- **支持内核**: 2.6.18 至最新 Linux 内核

## 目录结构

```
dattobd/
├── src/                    # 内核模块源代码 (核心)
│   ├── *.c, *.h            # 驱动实现文件
│   ├── configure-tests/    # 内核特性检测
│   ├── genconfig.sh        # 配置生成脚本
│   └── Makefile            # 内核模块构建
├── app/                    # 用户空间 CLI 工具
│   └── dbdctl.c            # dbdctl 命令行工具
├── lib/                    # 用户空间共享库
│   ├── libdattobd.c        # 库实现
│   └── libdattobd.h        # 公共 API 头文件
├── utils/                  # 辅助工具
│   └── update-img.c        # 增量镜像更新工具
├── tests/                  # Python 测试套件
├── dist/                   # 打包配置 (RPM/DEB)
├── doc/                    # 文档
└── Makefile                # 顶层构建文件
```

## 核心架构

### 关键组件

| 组件 | 文件 | 功能 |
|------|------|------|
| 模块控制 | `module_control.c` | 模块初始化、全局参数、proc 接口 |
| COW 管理器 | `cow_manager.c/h` | 写时复制文件管理、块映射 |
| 快照设备 | `snap_device.c/h` | 快照设备结构和管理 |
| I/O 追踪 | `tracer.c/h` | 块设备 I/O 拦截和处理 |
| ftrace 钩子 | `ftrace_hooking.c/h` | 使用 ftrace 拦截内核函数 |
| kretprobe 钩子 | `kretprobe_hooking.c/h` | 使用 kretprobe 拦截 |
| BIO 辅助 | `bio_helper.c/h` | BIO 操作封装 |
| Netlink 通信 | `netlink_handlers.c/h` | 用户空间通信 |

### 数据流

```
用户空间 (dbdctl)
        │
        ▼ Netlink Socket
┌───────────────────┐
│  netlink_handlers │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐     挂载/卸载事件
│     tracer        │◄──────────────────── ftrace/kretprobe 钩子
└────────┬──────────┘
         │ I/O 拦截
         ▼
┌───────────────────┐
│   cow_manager     │◄──── COW 文件 (/.datto)
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│   块设备 I/O      │
└───────────────────┘
```

### 设备状态机

```
状态 (sd_state):
├── SNAPSHOT (0)     - 快照模式
└── INCREMENTAL (1)  - 增量模式

状态标志 (sd_state bits):
├── ACTIVE (1)       - 活动状态 (设备已挂载)
├── DORMANT (0)      - 休眠状态 (设备已卸载)
└── UNVERIFIED (2)   - 未验证状态 (启动时/重载中)

状态转换:
UNVERIFIED ──挂载──► ACTIVE ──卸载──► DORMANT
    ▲                                      │
    └──────────── 重载 ◄───────────────────┘
```

## 编码规范

### 代码风格

- **缩进**: 使用 Tab (4 字符宽)
- **行宽**: 最大 100 字符
- **大括号**: 函数定义换行，控制语句不换行
- **命名**: 下划线命名法 (snake_case)
- **注释**: 使用 `/* */` 风格，文件头使用 SPDX 标识

### 文件头模板

```c
// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */
```

### 内核 API 兼容性

项目通过 `configure-tests/` 目录下的特性检测实现跨内核兼容：

```c
// 使用条件编译适配不同内核版本
#ifdef HAVE_BIO_ALLOC
    bio = bio_alloc(GFP_NOIO, nr_vecs);
#else
    bio = bio_alloc_bioset(GFP_NOIO, nr_vecs, &dev->sd_bioset);
#endif
```

### 常用宏和模式

```c
// 日志宏
LOG_DEBUG("message: %d", value);
LOG_ERROR(ret, "error description");

// 错误处理
if (ret) {
    LOG_ERROR(ret, "operation failed");
    goto error;
}

// 内存分配 (内核空间)
void *ptr = kmalloc(size, GFP_KERNEL);
void *ptr = vzalloc(size);  // 大块内存
kfree(ptr);
```

## 构建系统

### 编译命令

```bash
# 编译内核模块
make driver

# 编译用户空间库
make library

# 编译 CLI 工具
make application

# 编译所有
make all

# 清理
make clean

# 安装
sudo make install

# 打包 (DEB/RPM)
make deb
make rpm
```

### 构建环境要求

- **内核版本**: 5.10+
- **编译工具**: `gcc`, `make`, `clang`, `clangd`, `compiledb`
- **开发库**: `libkmod`, `libuuid`, `libblkid`
- **构建系统**: `debbuild` (Debian) 或 `rpmbuild` (RPM)

### 开发和调试

```bash

## 编译命令并生成 compile_commands.json
CC=clang-14 LD=ld.lld-14 compiledb make -j4 && mv compile_commands.json build

## 清理构建文件
make clean && rm -rf build/compile_commands.json build
```

### 内核模块构建流程

1. `genconfig.sh` 检测内核特性 → 生成 `kernel-config.h`
2. 内核构建系统 (`/lib/modules/$(uname -r)/build`) 编译模块
3. 输出 `dattobd.ko`

### clangd 配置

使用 `compiledb` 生成 `compile_commands.json`：

```bash
cd src
compiledb -o compile_commands.json make
```

项目包含 `.clangd` 配置文件，自动过滤 GCC 特有参数。

## 关键数据结构

### cow_header (COW 文件头)

```c
struct cow_header {
    uint32_t magic;           // 0x12B8 (4776)
    uint32_t flags;           // 状态标志
    uint64_t fpos;            // 当前文件偏移
    uint64_t fsize;           // 文件大小
    uint64_t seqid;           // 快照序列号
    uint8_t uuid[16];         // UUID
    uint64_t version;         // 格式版本
    uint64_t nr_changed_blocks;
};
```

### snap_device (快照设备)

```c
struct snap_device {
    unsigned int sd_minor;           // 设备次设备号
    unsigned long sd_state;          // 状态
    struct bdev_wrapper *sd_base_dev; // 底层块设备
    struct cow_manager *sd_cow;      // COW 管理器
    struct bio_queue sd_cow_bios;    // COW BIO 队列
    struct bio_queue sd_orig_bios;   // 原始 BIO 队列
    // ...
};
```

### cow_section (COW 区段)

```c
struct cow_section {
    char has_data;        // 是否有数据
    unsigned long usage;  // 使用计数 (LRU)
    uint64_t *mappings;   // 块映射数组
};
```

## 用户空间 API

### dbdctl 命令

```bash
# 创建快照
dbdctl setup-snapshot <block_device> <cow_file> <minor>

# 重载快照
dbdctl reload-snapshot <block_device> <cow_file> <minor>

# 转换到增量模式
dbdctl transition-to-incremental <minor>

# 转换到快照模式
dbdctl transition-to-snapshot <cow_file> <minor>

# 销毁设备
dbdctl destroy <minor>

# 查看信息
dbdctl info <minor>
```

### libdattobd API

```c
// 设置快照
int dattobd_setup_snapshot(const char *bdev, const char *cow,
                           unsigned int minor, unsigned long cache_size);

// 转换到增量模式
int dattobd_transition_incremental(unsigned int minor);

// 销毁设备
int dattobd_destroy(unsigned int minor);
```

## Netlink 通信

使用 Netlink Socket (Unit 25) 进行内核-用户空间通信：

```c
enum msg_type {
    MSG_SETUP_SNAP = 2,
    MSG_RELOAD_SNAP = 3,
    MSG_RELOAD_INC = 4,
    MSG_DESTROY = 5,
    MSG_TRANSITION_INC = 6,
    MSG_TRANSITION_SNAP = 7,
    // ...
};
```

## 测试

测试框架位于 `tests/` 目录，使用 Python：

```bash
# 运行测试
python -m pytest tests/
```

测试文件：
- `test_snapshot.py` - 快照功能测试
- `test_transition_incremental.py` - 状态转换测试
- `test_destroy.py` - 销毁功能测试

## 常见开发任务

### 添加新的内核 API 适配

1. 在 `src/configure-tests/feature-tests/` 创建检测文件
2. 在 `genconfig.sh` 添加检测逻辑
3. 在代码中使用 `#ifdef HAVE_XXX` 条件编译

### 添加新的 Netlink 命令

1. 在 `dattobd.h` 的 `enum msg_type` 添加消息类型
2. 在 `netlink_handlers.c` 添加处理函数
3. 在 `lib/libdattobd.c` 添加用户空间 API

### 调试

```bash
# 启用调试日志
echo 1 > /sys/module/dattobd/parameters/debug

# 查看内核日志
dmesg | grep dattobd

# 查看设备状态
cat /proc/datto-info
```

## 重要注意事项

1. **内核 API 稳定性**: 内核 API 在不同版本间可能变化，始终使用特性检测
2. **内存安全**: 使用 `GFP_ATOMIC` 在原子上下文，`GFP_KERNEL` 在进程上下文
3. **锁**: 注意锁的获取顺序，避免死锁
4. **错误处理**: 所有内核函数调用都应检查返回值
5. **不要使用浮点数**: 内核空间不支持浮点运算

## 相关文档

- [README.md](README.md) - 项目介绍
- [INSTALL.md](INSTALL.md) - 安装指南
- [doc/STRUCTURE.md](doc/STRUCTURE.md) - COW 文件结构详解
- [doc/dbdctl.8.md](doc/dbdctl.8.md) - CLI 工具手册
