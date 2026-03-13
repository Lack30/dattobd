// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

/*
 * 声明 block change stream 使用的有界内核 ring buffer 及其基础记录格式。
 */

#ifndef BLOCK_CHANGE_STREAM_RING_H_
#define BLOCK_CHANGE_STREAM_RING_H_

#include "dattobd.h"
#include "includes.h"

struct block_change_stream_ring {
    spinlock_t lock;
    uint8_t *data;
    uint32_t capacity;
    uint32_t head;
    uint32_t tail;
    uint32_t used;
    uint64_t dropped_records;
    uint64_t dropped_bytes;
};

/**
 * block_change_stream_ring_alloc() - 分配并初始化一个 block change stream ring。
 * @capacity: ring 可用字节数。
 *
 * Return: 成功时返回 ring 指针，失败时返回 NULL。
 */
struct block_change_stream_ring *block_change_stream_ring_alloc(uint32_t capacity);

/**
 * block_change_stream_ring_free() - 释放 block change stream ring。
 * @ring: 要释放的 ring。
 */
void block_change_stream_ring_free(struct block_change_stream_ring *ring);

/**
 * block_change_stream_ring_write() - 以原子方式向 ring 写入一条记录。
 * @ring: 目标 ring。
 * @record: 记录起始地址。
 * @length: 记录长度。
 *
 * Return:
 * * 0 - 成功。
 * * -ENOSPC - ring 空间不足。
 * * -EINVAL - 参数非法。
 */
int block_change_stream_ring_write(struct block_change_stream_ring *ring, const void *record,
                                   uint32_t length);

/**
 * block_change_stream_ring_bytes_used() - 查询 ring 当前已使用字节数。
 * @ring: 要查询的 ring。
 *
 * Return: 已使用字节数。
 */
uint32_t block_change_stream_ring_bytes_used(const struct block_change_stream_ring *ring);

/**
 * block_change_stream_ring_capacity() - 查询 ring 总容量。
 * @ring: 要查询的 ring。
 *
 * Return: ring 总容量字节数。
 */
uint32_t block_change_stream_ring_capacity(const struct block_change_stream_ring *ring);

/**
 * block_change_stream_ring_read_user() - 从 ring 读取并消费最多 @length 字节到用户空间。
 * @ring: 源 ring。
 * @buf: 用户空间缓冲区。
 * @length: 希望读取的字节数。
 *
 * Return:
 * * >0 - 实际读取的字节数。
 * * 0 - ring 当前为空。
 * * -EFAULT - 复制到用户空间失败。
 * * -EINVAL - 参数非法。
 */
ssize_t block_change_stream_ring_read_user(struct block_change_stream_ring *ring, char __user *buf,
                                           size_t length);

#endif /* BLOCK_CHANGE_STREAM_RING_H_ */
