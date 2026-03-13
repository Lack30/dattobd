# Block Change Stream 实现 Checklist

## 1. 命名统一

- [ ] 将 `binlog_export` 全部重命名为 `block_change_stream`
- [ ] 统一缩写为 `bcs`
- [ ] 用户态与文档统一使用 `block change stream`、`dbdbcsd`、`*.bcslog`

## 2. ABI 冻结

- [ ] 定义 `bcs_file_header`
- [ ] 定义 `bcs_record_header`
- [ ] 定义 `bcs_ring_header`
- [ ] 定义 `WRITE/CHECKPOINT/ROTATE` record 类型
- [ ] 定义 netlink 消息：`SUBSCRIBE/UNSUBSCRIBE/FLUSH/CHECKPOINT/STATUS/CONFIGURE`
- [ ] 定义 ioctl：`GET_INFO/CONSUME/FLUSH/GET_STATS`

## 3. 内核文件改动

- [ ] 重命名 `src/binlog_export.h` -> `src/block_change_stream.h`
- [ ] 重命名 `src/binlog_export.c` -> `src/block_change_stream.c`
- [ ] 新增 `src/block_change_stream_ring.h`
- [ ] 新增 `src/block_change_stream_ring.c`
- [ ] 新增 `src/block_change_stream_chrdev.h`
- [ ] 新增 `src/block_change_stream_chrdev.c`
- [ ] 建议新增 `src/block_change_stream_types.h`

## 4. 内核接入点

- [ ] `src/tracer.c` - 在 `inc_trace_bio()` 接入 payload 捕获
  - [ ] 支持整块写
  - [ ] 支持 partial write patch
- [ ] `src/snap_handle.c` - 将 hook 改为 `block_change_set_for_stream()`
  - [ ] 保持只负责异步 flush 提示
- [ ] `src/snap_device.h` - 增加 `struct block_change_stream *sd_bcs;`
- [ ] `src/tracer.c`
  - [ ] 在进入 incremental 时初始化 `sd_bcs`
  - [ ] 在退出 incremental / destroy / fail 时 flush 并释放 `sd_bcs`
- [ ] `src/module_control.c` - 注册/注销 BCS 全局资源与 chrdev

## 5. Final-value Cache

- [ ] 实现 per-block final-value cache
- [ ] 采用 hash bucket + per-bucket lock
- [ ] entry 状态至少包含 `DIRTY/QUEUED/FLUSHING`
- [ ] 同一 block 多次写只保留最后值
- [ ] checkpoint/rotate 时统一清理 entry

## 6. Partial Write

- [ ] cache 已有 block：直接 patch
- [ ] cache 没有 block：先读底层当前 block，再 patch
- [ ] 底层读必须走 passthrough，避免递归 tracing
- [ ] 明确 `WRITE_ZEROES` 处理方式

## 7. Stream Ring

- [ ] 每个 `minor` 一个 ring
- [ ] 支持 producer/consumer 指针
- [ ] 支持 padding record 处理 wrap-around
- [ ] 支持 high/critical watermark
- [ ] 提供 `read/poll` fallback
- [ ] 提供 `mmap` fast path

## 8. 字符设备

- [ ] 设备名：`/dev/dattobcs<minor>`
- [ ] 实现 `open/release/read/poll/mmap/ioctl`
- [ ] 第一版只支持单 reader
- [ ] reader 断开时更新状态并参与背压判断

## 9. 控制面

- [ ] `src/dattobd.h` 增加 BCS 消息与参数结构
- [ ] `src/netlink_handlers.c` 增加 BCS handlers
- [ ] `src/userspace_copy_helpers.h/.c` 增加参数解析
- [ ] `lib/libdattobd.h/.c` 增加 BCS API
- [ ] `app/dbdctl.c` 增加 BCS 子命令

## 10. 状态切换

- [ ] `transition-to-incremental`：初始化 BCS 窗口
- [ ] `flush/checkpoint`：flush dirty blocks，写 checkpoint
- [ ] `transition-to-snapshot`：强制 flush，写 rotate/checkpoint，关闭窗口
- [ ] 不跨 `snap_device` 迁移复杂 BCS 内存状态

## 11. 背压

- [ ] 实现 `high watermark`
- [ ] 实现 `critical watermark`
- [ ] `critical` 时 `fail-closed`
- [ ] 暴露 stats：dirty blocks、cache entries、ring used/free、reader lag、flush latency、fail reason

## 12. 用户态工具

- [ ] 新增 `app/dbdbcsd.c`
  - [ ] netlink subscribe/configure
  - [ ] 打开 `/dev/dattobcs<minor>`
  - [ ] 优先 `mmap`，失败 fallback `read`
  - [ ] 顺序写 `.bcslog`
  - [ ] 支持 checkpoint/fsync
- [ ] 新增 `app/apply-bcslog.c`
  - [ ] 校验头部
  - [ ] 顺序回放 `WRITE`
  - [ ] 识别 `CHECKPOINT`

## 13. 构建系统

- [ ] 更新顶层 `Makefile`
- [ ] 增加 `dbdbcsd`
- [ ] 增加 `apply-bcslog`

## 14. 注释要求

- [ ] 所有公共接口补 kernel-doc
- [ ] 所有 `register_*` / `unregister_*` 补 kernel-doc
- [ ] partial write、passthrough 读、背压、ring wrap-around、memory ordering 补块注释
- [ ] 新文件补文件头职责说明

## 15. 文档

- [ ] 新增 `doc/BLOCK_CHANGE_STREAM.md`
- [ ] 新增 `doc/BLOCK_CHANGE_STREAM_FORMAT.md`
- [ ] 说明架构、窗口语义、背压、设备接口、文件格式

## 16. 测试

- [ ] 同一 block 多次写只保留最后值
- [ ] partial write 回放正确
- [ ] 连续 block 合并正确
- [ ] `read` / `mmap` 输出一致
- [ ] reader 慢 / reader 断开 / ring 满触发 fail-closed
- [ ] incremental -> snapshot 边界正确
- [ ] `.bcslog` 回放结果正确

## 17. 建议开发顺序

1. 冻结 ABI
2. 内核骨架 + 生命周期
3. payload 捕获
4. final-value cache
5. ring + `read/poll`
6. `mmap`
7. netlink/lib/CLI
8. `dbdbcsd`
9. `apply-bcslog`
10. 测试与压测
