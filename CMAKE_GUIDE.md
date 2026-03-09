# CMake 构建系统使用指南

本文档说明如何使用 CMake 管理 dattobd 项目。

## 概述

CMake 构建系统提供了以下优势：

- **跨平台支持**: 统一的构建接口
- **IDE 集成**: 原生支持 VSCode、CLion、Qt Creator 等
- **依赖管理**: 自动处理库依赖
- **包生成**: 支持 DEB、RPM、TGZ 打包
- **编译数据库**: 自动生成 `compile_commands.json` 用于 clangd

## 目录结构

```
dattobd/
├── CMakeLists.txt              # 顶层 CMake 配置
├── CMakePresets.json          # CMake 预设配置
├── cmake/
│   └── dattobdConfig.cmake.in # CMake 包配置模板
├── src/CMakeLists.txt          # 内核模块构建
├── lib/CMakeLists.txt          # 用户空间库构建
├── app/CMakeLists.txt          # CLI 工具构建
└── utils/CMakeLists.txt         # 辅助工具构建
```

## 快速开始

### 基本构建

```bash
# 配置项目 (默认构建所有组件)
cmake -S . -B build

# 编译
cmake --build build

# 安装
sudo cmake --install build
```

### 使用预设配置

```bash
# 列出所有预设
cmake --list-presets

# 使用预设配置
cmake --preset default
cmake --preset debug
cmake --preset release
cmake --preset user-space-only
cmake --preset driver-only
cmake --preset clang

# 使用预设构建
cmake --build --preset default
cmake --build --preset debug
```

## 构建选项

### 命令行选项

| 选项 | 默认值 | 描述 |
|------|---------|------|
| `BUILD_DRIVER` | ON | 构建内核模块 |
| `BUILD_LIBRARY` | ON | 构建用户空间库 |
| `BUILD_APPLICATION` | ON | 构建 CLI 应用 (dbdctl) |
| `BUILD_UTILS` | ON | 构建辅助工具 (update-img) |
| `BUILD_SHARED_LIBS` | ON | 构建共享库 (.so) |
| `BUILD_STATIC_LIBS` | ON | 构建静态库 (.a) |
| `INSTALL_HEADERS` | ON | 安装头文件 |
| `KERNEL_VERSION` | (自动检测) | 目标内核版本 |
| `KERNEL_SOURCE_DIR` | (自动检测) | 内核源码目录 |

### 配置示例

```bash
# 仅构建用户空间组件
cmake -S . -B build-userspace \
    -DBUILD_DRIVER=OFF \
    -DBUILD_LIBRARY=ON \
    -DBUILD_APPLICATION=ON \
    -DBUILD_UTILS=ON

# 仅构建内核模块
cmake -S . -B build-driver \
    -DBUILD_DRIVER=ON \
    -DBUILD_LIBRARY=OFF \
    -DBUILD_APPLICATION=OFF \
    -DBUILD_UTILS=OFF

# 为特定内核版本构建
cmake -S . -B build-kernel-5.15 \
    -DKERNEL_VERSION=5.15.0-1 \
    -DKERNEL_SOURCE_DIR=/usr/src/linux-headers-5.15.0-1

# 使用 Clang 编译
cmake -S . -B build-clang \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++

# Debug 构建
cmake -S . -B build-debug \
    -DCMAKE_BUILD_TYPE=Debug

# Release 构建
cmake -S . -B build-release \
    -DCMAKE_BUILD_TYPE=Release
```

## 构建目标

### 可用目标

```bash
# 构建所有目标
cmake --build build

# 构建特定目标
cmake --build build --target driver
cmake --build build --target dattobd
cmake --build build --target dbdctl
cmake --build build --target update-img

# 清理
cmake --build build --target clean
cmake --build build --target driver-clean

# 安装
cmake --install build

# 打包
cpack --config build
cpack --config build -G DEB
cpack --config build -G RPM
cpack --config build -G TGZ
```

## IDE 集成

### VSCode

安装 CMake Tools 扩展后，使用预设配置：

```bash
# 配置项目
cmake --preset default

# VSCode 会自动识别并使用 compile_commands.json
```

### CLion

CLion 原生支持 CMake，直接打开项目即可：

1. File → Open → 选择 dattobd 目录
2. 选择预设配置
3. 点击 Build 按钮

### Qt Creator

1. File → Open File or Project → 选择 CMakeLists.txt
2. 选择构建目录
3. 配置并构建

## 编译数据库

CMake 自动生成 `compile_commands.json`，用于：

- **clangd**: 代码补全和诊断
- **clang-tidy**: 静态分析
- **clang-query**: 查询代码库

位置：`build/compile_commands.json`

## 交叉编译

```bash
# 交叉编译到 ARM64
cmake -S . -B build-arm64 \
    -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
    -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
    -DKERNEL_VERSION=5.10.0
```

## 高级用法

### Ninja 构建系统

```bash
# 使用 Ninja (更快)
cmake -S . -B build-ninja -G Ninja
ninja -C build-ninja
```

### 多配置生成器

```bash
# 生成 Debug 和 Release 配置
cmake -S . -B build-multi -G "Unix Makefiles" \
    -DCMAKE_CONFIGURATION_TYPES="Debug;Release"

# 构建特定配置
cmake --build build-multi --config Debug
cmake --build build-multi --config Release
```

### 自定义安装路径

```bash
# 安装到自定义目录
cmake -S . -B build-custom \
    -DCMAKE_INSTALL_PREFIX=/opt/dattobd

# 安装
sudo cmake --install build-custom
```

## 与原 Makefile 的对比

| 功能 | Makefile | CMake |
|------|----------|--------|
| 简单性 | 简单 | 稍复杂 |
| IDE 集成 | 有限 | 原生支持 |
| 跨平台 | 有限 | 良好 |
| 依赖管理 | 手动 | 自动 |
| 编译数据库 | 需 compiledb | 自动生成 |
| 包生成 | 需要单独脚本 | 内置支持 |

## 故障排除

### 内核模块构建失败

```bash
# 检查内核头文件
ls /lib/modules/$(uname -r)/build

# 检查 genconfig.sh 输出
cd src && ./genconfig.sh $(uname -r)

# 手动运行内核构建
cd build/src
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```

### 找不到内核头文件

```bash
# 安装内核头文件
sudo apt-get install linux-headers-$(uname -r)
sudo apt-get install kernel-devel
```

### CMake 版本过低

```bash
# 检查 CMake 版本
cmake --version

# 需要至少 3.16
# 升级 CMake
sudo apt-get install cmake
```

## 迁移指南

### 从 Makefile 迁移

```bash
# 原来的命令
make all
make install

# 等效的 CMake 命令
cmake --preset default
cmake --build --preset default
sudo cmake --install build
```

### 保留 Makefile

CMake 和 Makefile 可以共存：

```bash
# 使用 Makefile
make driver

# 使用 CMake
cmake --build build --target driver
```

## 最佳实践

1. **使用预设配置**: 统一团队构建环境
2. **分离构建目录**: 保持源码目录清洁
3. **使用编译数据库**: 启用 IDE 智能功能
4. **版本控制**: 忽略 `build/` 目录
5. **持续集成**: 使用 CMake 的测试和打包功能

## 示例工作流

### 完整开发周期

```bash
# 1. 配置项目
cmake --preset debug

# 2. 编译
cmake --build --preset debug

# 3. 测试
ctest --preset debug

# 4. 安装
sudo cmake --install build-debug

# 5. 清理
cmake --build build-debug --target clean

# 6. 重新配置
cmake --preset debug
```

### 发布构建

```bash
# 1. 配置 Release
cmake --preset release

# 2. 编译
cmake --build --preset release

# 3. 运行测试
ctest --preset release

# 4. 打包
cpack --config build-release -G DEB
cpack --config build-release -G RPM

# 5. 安装
sudo dpkg -i build-release/*.deb
# 或
sudo rpm -i build-release/*.rpm
```

## 相关文档

- [AGENTS.md](AGENTS.md) - 项目开发指南
- [INSTALL.md](INSTALL.md) - 安装说明
- [README.md](README.md) - 项目概述
