// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

/*
 * 实现 block change stream 的有界内核 ring buffer，为后续 read/poll/mmap 数据面提供基础。
 */

#include "block_change_stream_ring.h"

static void bcs_ring_copy_in(struct block_change_stream_ring *ring, uint32_t pos, const void *src,
                             uint32_t len)
{
    uint32_t first_len = min_t(uint32_t, len, ring->capacity - pos);

    memcpy(ring->data + pos, src, first_len);
    if (first_len != len)
        memcpy(ring->data, (const uint8_t *)src + first_len, len - first_len);
}

static int bcs_ring_copy_out_user(struct block_change_stream_ring *ring, uint32_t pos,
                                  char __user *dst, uint32_t len)
{
    uint32_t first_len = min_t(uint32_t, len, ring->capacity - pos);

    if (copy_to_user(dst, ring->data + pos, first_len))
        return -EFAULT;

    if (first_len != len && copy_to_user(dst + first_len, ring->data, len - first_len))
        return -EFAULT;

    return 0;
}

static void bcs_ring_copy_out(struct block_change_stream_ring *ring, uint32_t pos, void *dst,
                              uint32_t len)
{
    uint32_t first_len = min_t(uint32_t, len, ring->capacity - pos);

    memcpy(dst, ring->data + pos, first_len);
    if (first_len != len)
        memcpy((uint8_t *)dst + first_len, ring->data, len - first_len);
}

struct block_change_stream_ring *block_change_stream_ring_alloc(uint32_t capacity)
{
    struct block_change_stream_ring *ring;

    if (!capacity)
        return NULL;

    ring = kzalloc(sizeof(*ring), GFP_KERNEL);
    if (!ring)
        return NULL;

    ring->data = vzalloc(capacity);
    if (!ring->data) {
        kfree(ring);
        return NULL;
    }

    spin_lock_init(&ring->lock);
    ring->capacity = capacity;

    return ring;
}

void block_change_stream_ring_free(struct block_change_stream_ring *ring)
{
    if (!ring)
        return;

    if (ring->data)
        vfree(ring->data);
    kfree(ring);
}

int block_change_stream_ring_write(struct block_change_stream_ring *ring, const void *record,
                                   uint32_t length)
{
    unsigned long flags;

    if (!ring || !record || !length || length > ring->capacity)
        return -EINVAL;

    spin_lock_irqsave(&ring->lock, flags);
    if (ring->capacity - ring->used < length) {
        ring->dropped_records++;
        ring->dropped_bytes += length;
        spin_unlock_irqrestore(&ring->lock, flags);
        return -ENOSPC;
    }

    bcs_ring_copy_in(ring, ring->head, record, length);
    ring->head = (ring->head + length) % ring->capacity;
    ring->used += length;
    spin_unlock_irqrestore(&ring->lock, flags);

    return 0;
}

uint32_t block_change_stream_ring_bytes_used(const struct block_change_stream_ring *ring)
{
    if (!ring)
        return 0;

    return READ_ONCE(ring->used);
}

uint32_t block_change_stream_ring_capacity(const struct block_change_stream_ring *ring)
{
    if (!ring)
        return 0;

    return ring->capacity;
}

ssize_t block_change_stream_ring_read_user(struct block_change_stream_ring *ring, char __user *buf,
                                           size_t length)
{
    unsigned long flags;
    uint32_t read_len;
    uint32_t total_len = 0;
    uint32_t pos;
    struct bcs_record_header hdr;
    int ret;

    if (!ring || !buf || !length)
        return -EINVAL;

    spin_lock_irqsave(&ring->lock, flags);
    if (!ring->used) {
        spin_unlock_irqrestore(&ring->lock, flags);
        return 0;
    }

    pos = ring->tail;
    while (ring->used - total_len >= sizeof(hdr)) {
        bcs_ring_copy_out(ring, pos, &hdr, sizeof(hdr));
        if (hdr.length < sizeof(hdr) || hdr.length > ring->used - total_len)
            break;
        if (total_len + hdr.length > length)
            break;

        ret = bcs_ring_copy_out_user(ring, pos, buf + total_len, hdr.length);
        if (ret) {
            spin_unlock_irqrestore(&ring->lock, flags);
            return ret;
        }

        total_len += hdr.length;
        pos = (pos + hdr.length) % ring->capacity;
    }

    read_len = total_len;
    if (!read_len) {
        spin_unlock_irqrestore(&ring->lock, flags);
        return -ENOSPC;
    }

    ring->tail = (ring->tail + read_len) % ring->capacity;
    ring->used -= read_len;
    spin_unlock_irqrestore(&ring->lock, flags);

    return read_len;
}
