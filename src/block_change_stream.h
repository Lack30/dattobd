// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

/*
 * 声明 block change stream 的设备级生命周期、写入捕获与状态查询接口。
 */

#ifndef BLOCK_CHANGE_STREAM_H_
#define BLOCK_CHANGE_STREAM_H_

#include <linux/blk_types.h>

struct bio;
struct block_change_stream;
struct block_change_stream_status;
struct file;
typedef struct poll_table_struct poll_table;
struct snap_device;

/**
 * block_change_stream_global_init() - 初始化 block change stream 全局资源。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
int block_change_stream_global_init(void);

/**
 * block_change_stream_global_exit() - 释放 block change stream 全局资源。
 */
void block_change_stream_global_exit(void);

/**
 * block_change_stream_device_init() - 为增量设备创建 block change stream 状态。
 * @dev: 处于增量模式或即将进入增量模式的 &struct snap_device。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
int block_change_stream_device_init(struct snap_device *dev);

/**
 * block_change_stream_device_free() - 释放增量设备的 block change stream 状态。
 * @dev: 需要清理 stream 状态的 &struct snap_device。
 */
void block_change_stream_device_free(struct snap_device *dev);

/**
 * block_change_stream_open() - 为字符设备 reader 建立设备级访问状态。
 * @dev: 对应 minor 的 &struct snap_device。
 *
 * 第一版 block change stream 仅允许单 reader，以便销毁与背压语义保持简单。
 *
 * Return:
 * * 0 - 成功。
 * * -EBUSY - 已有 reader 占用。
 * * -ENODEV - 设备不支持 block change stream。
 */
int block_change_stream_open(struct snap_device *dev);

/**
 * block_change_stream_release() - 释放字符设备 reader 状态。
 * @dev: 对应 minor 的 &struct snap_device。
 */
void block_change_stream_release(struct snap_device *dev);

/**
 * block_change_stream_has_readers() - 判断 block change stream 是否仍被 reader 占用。
 * @dev: 要查询的设备。
 *
 * Return: 非 0 表示仍有活动 reader。
 */
int block_change_stream_has_readers(struct snap_device *dev);

/**
 * block_change_stream_capture_bio() - 在增量热路径采集一次写 BIO 的载荷统计。
 * @dev: 当前处理写入的增量设备。
 * @bio: 原始写 BIO。
 *
 * 当前实现先建立控制面与统计基础，不做真正的 ring/payload 导出；后续会在
 * 此入口中扩展最终值 block 缓存与用户态流式传输。
 */
void block_change_stream_capture_bio(struct snap_device *dev, struct bio *bio);

/**
 * block_change_stream_blocks_changed() - 记录异步增量线程确认的变更块范围。
 * @dev: 增量模式下的 &struct snap_device。
 * @block_start: 首个发生变更的 4 KiB block 编号。
 * @block_count: 连续变更 block 数。
 */
void block_change_stream_blocks_changed(struct snap_device *dev, sector_t block_start,
                                        sector_t block_count);

/**
 * block_change_stream_status() - 读取设备当前的 block change stream 统计信息。
 * @dev: 要查询的设备。
 * @status: 输出的状态结构。
 */
void block_change_stream_status(const struct snap_device *dev,
                                struct block_change_stream_status *status);

/**
 * block_change_stream_read() - 从设备的 block change stream ring 读取并消费数据。
 * @dev: 要读取的增量设备。
 * @buf: 用户空间缓冲区。
 * @length: 希望读取的字节数。
 * @nonblock: 非 0 表示按非阻塞方式读取。
 *
 * Return: 语义与字符设备 read(2) 一致。
 */
ssize_t block_change_stream_read(struct snap_device *dev, char __user *buf, size_t length,
                                 int nonblock);

/**
 * block_change_stream_poll() - 查询设备 stream 当前的可读性。
 * @dev: 要查询的增量设备。
 * @file: 当前打开的字符设备文件。
 * @wait: poll 上下文。
 *
 * Return: poll mask。
 */
__poll_t block_change_stream_poll(struct snap_device *dev, struct file *file, poll_table *wait);

#endif /* BLOCK_CHANGE_STREAM_H_ */
