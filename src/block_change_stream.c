// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

/*
 * 实现 block change stream 的设备状态、块缓存与基础统计逻辑，为后续 ring/mmap
 * 数据面提供可增量扩展的最终值缓存骨架。
 */

#include "block_change_stream.h"
#include "block_change_stream_ring.h"
#include "bio_helper.h"
#include "dattobd.h"
#include "includes.h"
#include "logging.h"
#include "snap_device.h"
#include "tracer_helper.h"

#include <linux/poll.h>

#define BCS_CACHE_BUCKETS 1024
#define BCS_BLOCK_VALID_FULL ((1U << SECTORS_PER_BLOCK) - 1)
#define BCS_DEFAULT_RING_CAPACITY (256 * 1024)

struct block_change_stream_entry {
    struct hlist_node node;
    sector_t block_no;
    unsigned int valid_mask;
    uint8_t data[COW_BLOCK_SIZE];
};

struct block_change_stream {
    spinlock_t lock;
    wait_queue_head_t read_wait;
    atomic_t readers;
    bool shutting_down;
    struct hlist_head buckets[BCS_CACHE_BUCKETS];
    struct block_change_stream_ring *ring;
    unsigned int minor;
    sector_t last_changed_block;
    sector_t last_changed_count;
    uint64_t last_recorded_jiffies;
    uint64_t captured_writes;
    uint64_t captured_bytes;
    uint64_t changed_ranges;
    uint64_t changed_blocks;
    uint64_t cached_blocks;
    uint64_t complete_blocks;
    uint64_t partial_blocks;
};

/**
 * bcs_bucket_index() - 计算块号对应的缓存桶索引。
 * @block_no: 相对被跟踪块设备起始处的 4 KiB block 编号。
 *
 * Return: 固定大小哈希表中的桶索引。
 */
static unsigned int bcs_bucket_index(sector_t block_no)
{
    return hash_64((uint64_t)block_no, ilog2(BCS_CACHE_BUCKETS));
}

/**
 * bcs_cache_lookup() - 在 block change stream 缓存中按 block 编号查找条目。
 * @bcs: 设备级 stream 状态。
 * @block_no: 相对块编号。
 *
 * Return: 找到时返回缓存条目，否则返回 NULL。
 */
static struct block_change_stream_entry *bcs_cache_lookup(struct block_change_stream *bcs,
                                                          sector_t block_no)
{
    struct block_change_stream_entry *entry;
    struct hlist_head *bucket = &bcs->buckets[bcs_bucket_index(block_no)];

    hlist_for_each_entry (entry, bucket, node) {
        if (entry->block_no == block_no)
            return entry;
    }

    return NULL;
}

/**
 * bcs_cache_get_or_alloc() - 查找或创建指定 block 的最终值缓存条目。
 * @bcs: 设备级 stream 状态。
 * @block_no: 相对块编号。
 *
 * 调用者必须持有 @bcs->lock。
 *
 * Return: 成功时返回缓存条目，分配失败返回 NULL。
 */
static struct block_change_stream_entry *bcs_cache_get_or_alloc(struct block_change_stream *bcs,
                                                                sector_t block_no)
{
    struct block_change_stream_entry *entry;
    struct hlist_head *bucket;

    entry = bcs_cache_lookup(bcs, block_no);
    if (entry)
        return entry;

    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return NULL;

    entry->block_no = block_no;
    bucket = &bcs->buckets[bcs_bucket_index(block_no)];
    hlist_add_head(&entry->node, bucket);
    bcs->cached_blocks++;
    bcs->partial_blocks++;

    return entry;
}

/**
 * bcs_update_valid_mask() - 按此次写入范围更新条目的完整度统计。
 * @bcs: 设备级 stream 状态。
 * @entry: 被更新的缓存条目。
 * @block_off: 本次写入在 block 内的字节偏移。
 * @len: 本次写入覆盖的字节数。
 *
 * block change stream 最终会为 partial write 引入底层 block 基线读取；当前阶段先按
 * 扇区粒度记录哪些字节范围已被观测到，以便区分完整 block 和部分 block。
 */
static void bcs_update_valid_mask(struct block_change_stream *bcs,
                                  struct block_change_stream_entry *entry, unsigned int block_off,
                                  unsigned int len)
{
    unsigned int start_sector = block_off >> SECTOR_SHIFT;
    unsigned int end_sector = (block_off + len + SECTOR_SIZE - 1) >> SECTOR_SHIFT;
    unsigned int new_mask;
    unsigned int old_mask = entry->valid_mask;

    new_mask = GENMASK(end_sector - 1, start_sector);
    entry->valid_mask |= new_mask;

    if (old_mask != BCS_BLOCK_VALID_FULL && entry->valid_mask == BCS_BLOCK_VALID_FULL) {
        if (bcs->partial_blocks)
            bcs->partial_blocks--;
        bcs->complete_blocks++;
    }
}

/**
 * bcs_capture_bytes() - 将 BIO 中的一段数据写入最终值缓存。
 * @bcs: 设备级 stream 状态。
 * @rel_byte: 相对设备起始位置的字节偏移。
 * @src: 本次写入的数据源。
 * @len: 本次写入的长度。
 *
 * 当前阶段维护块缓存和完整度标记；对于第一次出现的 partial write，会先从底层设备
 * 读取该 block 的当前内容，再将本次写入 patch 进去。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
/**
 * bcs_read_base_block() - 从被跟踪块设备读取一个完整的 4 KiB block。
 * @dev: block change stream 所属的 &struct snap_device。
 * @block_no: 相对被跟踪设备起始位置的 block 编号。
 * @dst: 输出缓冲区，长度至少为一个 COW block。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
static int bcs_read_base_block(struct snap_device *dev, sector_t block_no, uint8_t *dst)
{
    int ret;
    int bytes;
    struct page *page;
    struct bio *bio;
    struct block_device *bdev = dev->sd_base_dev->bdev;
    char *data;

#ifdef HAVE_BIO_ALLOC
    bio = bio_alloc(GFP_NOIO, 1);
#else
    bio = bio_alloc(bdev, 1, 0, GFP_KERNEL);
#endif
    if (!bio) {
        LOG_ERROR(-ENOMEM, "error allocating block change stream read bio");
        return -ENOMEM;
    }

    page = alloc_page(GFP_NOIO);
    if (!page) {
        bio_free_clone(bio);
        LOG_ERROR(-ENOMEM, "error allocating block change stream read page");
        return -ENOMEM;
    }

    dattobd_bio_set_dev(bio, bdev);
    dattobd_set_bio_ops(bio, REQ_OP_READ, 0);
    bio_sector(bio) = dev->sd_sect_off + block_no * SECTORS_PER_BLOCK;

    bytes = bio_add_page(bio, page, COW_BLOCK_SIZE, 0);
    if (bytes != COW_BLOCK_SIZE) {
        __free_page(page);
        bio_free_clone(bio);
        LOG_ERROR(-EFAULT, "bio_add_page failed for block change stream base read");
        return -EFAULT;
    }

    ret = dattobd_submit_bio_wait(bio);
    if (ret) {
        bio_free_clone(bio);
        LOG_ERROR(ret, "error reading base block for block change stream");
        return ret;
    }

    data = kmap(page);
    memcpy(dst, data, COW_BLOCK_SIZE);
    kunmap(page);

    bio_free_clone(bio);

    return 0;
}

static int bcs_capture_bytes(struct block_change_stream *bcs, u64 rel_byte, const uint8_t *src,
                             unsigned int len, struct snap_device *dev)
{
    unsigned long flags;
    unsigned int chunk_len;
    unsigned int block_off;
    struct block_change_stream_entry *entry;
    sector_t block_no;
    uint8_t *baseline = NULL;
    bool needs_baseline;
    int ret = 0;

    while (len) {
        block_no = div_u64(rel_byte, COW_BLOCK_SIZE);
        block_off = rel_byte - (u64)block_no * COW_BLOCK_SIZE;
        chunk_len = min_t(unsigned int, len, COW_BLOCK_SIZE - block_off);
        needs_baseline = false;

        spin_lock_irqsave(&bcs->lock, flags);
        entry = bcs_cache_lookup(bcs, block_no);
        spin_unlock_irqrestore(&bcs->lock, flags);

        if (!entry && (block_off != 0 || chunk_len != COW_BLOCK_SIZE))
            needs_baseline = true;

        if (needs_baseline) {
            if (!baseline) {
                baseline = kmalloc(COW_BLOCK_SIZE, GFP_ATOMIC);
                if (!baseline) {
                    LOG_ERROR(-ENOMEM, "error allocating baseline buffer for block change stream");
                    return -ENOMEM;
                }
            }

            ret = bcs_read_base_block(dev, block_no, baseline);
            if (ret)
                goto out;
        }

        spin_lock_irqsave(&bcs->lock, flags);
        entry = bcs_cache_get_or_alloc(bcs, block_no);
        if (!entry) {
            spin_unlock_irqrestore(&bcs->lock, flags);
            LOG_ERROR(-ENOMEM, "error allocating block change stream cache entry");
            ret = -ENOMEM;
            goto out;
        }

        if (!entry->valid_mask) {
            if (needs_baseline)
                memcpy(entry->data, baseline, COW_BLOCK_SIZE);
            else
                memset(entry->data, 0, COW_BLOCK_SIZE);
        }

        memcpy(entry->data + block_off, src, chunk_len);
        bcs_update_valid_mask(bcs, entry, block_off, chunk_len);
        bcs->last_recorded_jiffies = get_jiffies_64();
        spin_unlock_irqrestore(&bcs->lock, flags);

        src += chunk_len;
        len -= chunk_len;
        rel_byte += chunk_len;
    }

out:
    if (baseline)
        kfree(baseline);

    return ret;
}

/**
 * bcs_cache_free_all() - 释放设备上所有 block change stream 缓存条目。
 * @bcs: 设备级 stream 状态。
 */
static void bcs_cache_free_all(struct block_change_stream *bcs)
{
    unsigned int idx;
    struct block_change_stream_entry *entry;
    struct hlist_node *tmp;

    for (idx = 0; idx < BCS_CACHE_BUCKETS; idx++) {
        hlist_for_each_entry_safe (entry, tmp, &bcs->buckets[idx], node) {
            hlist_del(&entry->node);
            kfree(entry);
        }
    }
}

/**
 * bcs_queue_range_record() - 将已确认的块范围信息写入内核 ring。
 * @bcs: 设备级 stream 状态。
 *
 * 当前阶段 ring 仅作为后续用户态数据面的内核缓冲雏形，先写入简化的范围记录，后续会
 * 扩展为包含 payload 的最终值记录。
 */
static void bcs_queue_range_record(struct block_change_stream *bcs)
{
    struct bcs_record_range record;

    if (!bcs->ring)
        return;

    memset(&record, 0, sizeof(record));
    record.hdr.type = BCS_RECORD_RANGE;
    record.hdr.length = sizeof(record);
    record.first_block = bcs->last_changed_block;
    record.block_count = bcs->last_changed_count;
    record.captured_writes = bcs->captured_writes;
    record.changed_blocks = bcs->changed_blocks;

    if (block_change_stream_ring_write(bcs->ring, &record, sizeof(record)) == -ENOSPC)
        LOG_WARN("block change stream ring is full; dropping range record for minor %u",
                 bcs->minor);
    else
        wake_up_interruptible(&bcs->read_wait);
}

/**
 * bcs_queue_block_record() - 将一个已完整缓存的 block 作为 payload 记录写入 ring。
 * @bcs: 设备级 stream 状态。
 * @entry: 要导出的缓存条目。
 *
 * 当前阶段按单 block record 导出，保证 read/poll 路径已经可以把真实 payload 送到
 * 用户态；后续再在此基础上做连续 block 聚合。
 */
static void bcs_queue_block_record(struct block_change_stream *bcs,
                                   const struct block_change_stream_entry *entry)
{
    struct bcs_record_block *record;

    if (!bcs->ring)
        return;

    record = kmalloc(sizeof(*record), GFP_NOIO);
    if (!record) {
        LOG_ERROR(-ENOMEM, "error allocating block change stream block record");
        return;
    }

    memset(record, 0, sizeof(*record));
    record->hdr.type = BCS_RECORD_BLOCK;
    record->hdr.length = sizeof(*record);
    record->block_no = entry->block_no;
    record->valid_mask = entry->valid_mask;
    record->data_len = COW_BLOCK_SIZE;
    memcpy(record->data, entry->data, COW_BLOCK_SIZE);

    if (block_change_stream_ring_write(bcs->ring, record, sizeof(*record)) == -ENOSPC)
        LOG_WARN("block change stream ring is full; dropping block payload for minor %u block %llu",
                 bcs->minor, (unsigned long long)entry->block_no);
    else
        wake_up_interruptible(&bcs->read_wait);

    kfree(record);
}

int block_change_stream_global_init(void)
{
    return 0;
}

void block_change_stream_global_exit(void)
{
}

int block_change_stream_device_init(struct snap_device *dev)
{
    struct block_change_stream *bcs;
    unsigned int idx;

    if (dev->sd_bcs)
        return 0;

    bcs = kzalloc(sizeof(*bcs), GFP_KERNEL);
    if (!bcs) {
        LOG_ERROR(-ENOMEM, "error allocating block change stream state");
        return -ENOMEM;
    }

    spin_lock_init(&bcs->lock);
    init_waitqueue_head(&bcs->read_wait);
    atomic_set(&bcs->readers, 0);
    bcs->minor = dev->sd_minor;
    for (idx = 0; idx < BCS_CACHE_BUCKETS; idx++)
        INIT_HLIST_HEAD(&bcs->buckets[idx]);

    bcs->ring = block_change_stream_ring_alloc(BCS_DEFAULT_RING_CAPACITY);
    if (!bcs->ring) {
        kfree(bcs);
        LOG_ERROR(-ENOMEM, "error allocating block change stream ring");
        return -ENOMEM;
    }

    dev->sd_bcs = bcs;

    return 0;
}

void block_change_stream_device_free(struct snap_device *dev)
{
    if (!dev->sd_bcs)
        return;

    dev->sd_bcs->shutting_down = true;
    wake_up_interruptible_all(&dev->sd_bcs->read_wait);
    block_change_stream_ring_free(dev->sd_bcs->ring);
    bcs_cache_free_all(dev->sd_bcs);
    kfree(dev->sd_bcs);
    dev->sd_bcs = NULL;
}

int block_change_stream_open(struct snap_device *dev)
{
    struct block_change_stream *bcs;

    if (!dev || !dev->sd_bcs)
        return -ENODEV;

    bcs = dev->sd_bcs;
    if (atomic_cmpxchg(&bcs->readers, 0, 1) != 0)
        return -EBUSY;

    return 0;
}

void block_change_stream_release(struct snap_device *dev)
{
    if (!dev || !dev->sd_bcs)
        return;

    atomic_set(&dev->sd_bcs->readers, 0);
    wake_up_interruptible_all(&dev->sd_bcs->read_wait);
}

int block_change_stream_has_readers(struct snap_device *dev)
{
    if (!dev || !dev->sd_bcs)
        return 0;

    return atomic_read(&dev->sd_bcs->readers) != 0;
}

void block_change_stream_capture_bio(struct snap_device *dev, struct bio *bio)
{
    int ret;
    u64 rel_byte;
    uint8_t *data;
    unsigned long flags;
    struct block_change_stream *bcs = dev->sd_bcs;
    bio_iter_t iter;
    bio_iter_bvec_t bvec;

    if (!bcs)
        return;

    spin_lock_irqsave(&bcs->lock, flags);
    bcs->captured_writes++;
    bcs->captured_bytes += bio_size(bio);
    bcs->last_recorded_jiffies = get_jiffies_64();
    spin_unlock_irqrestore(&bcs->lock, flags);

    rel_byte = ((u64)(bio_sector(bio) - dev->sd_sect_off)) << SECTOR_SHIFT;

    bio_for_each_segment (bvec, bio, iter) {
        data = kmap(bvec.bv_page);
        ret = bcs_capture_bytes(bcs, rel_byte, (uint8_t *)data + bvec.bv_offset, bvec.bv_len, dev);
        kunmap(bvec.bv_page);
        if (ret)
            break;
        rel_byte += bvec.bv_len;
    }
}

void block_change_stream_blocks_changed(struct snap_device *dev, sector_t block_start,
                                        sector_t block_count)
{
    unsigned long flags;
    struct block_change_stream *bcs = dev->sd_bcs;
    struct block_change_stream_entry *entry;
    struct block_change_stream_entry *snapshot;
    sector_t block_no;

    if (!bcs)
        return;

    snapshot = kmalloc(sizeof(*snapshot), GFP_NOIO);
    if (!snapshot) {
        LOG_ERROR(-ENOMEM, "error allocating block change stream snapshot buffer");
        return;
    }

    spin_lock_irqsave(&bcs->lock, flags);
    bcs->changed_ranges++;
    bcs->changed_blocks += block_count;
    bcs->last_changed_block = block_start;
    bcs->last_changed_count = block_count;
    bcs->last_recorded_jiffies = get_jiffies_64();
    bcs_queue_range_record(bcs);
    spin_unlock_irqrestore(&bcs->lock, flags);

    for (block_no = block_start; block_no < block_start + block_count; block_no++) {
        spin_lock_irqsave(&bcs->lock, flags);
        entry = bcs_cache_lookup(bcs, block_no);
        if (!entry || entry->valid_mask != BCS_BLOCK_VALID_FULL) {
            spin_unlock_irqrestore(&bcs->lock, flags);
            continue;
        }

        memcpy(snapshot, entry, sizeof(*snapshot));
        spin_unlock_irqrestore(&bcs->lock, flags);

        bcs_queue_block_record(bcs, snapshot);
    }

    kfree(snapshot);
}

void block_change_stream_status(const struct snap_device *dev,
                                struct block_change_stream_status *status)
{
    unsigned long flags;
    struct block_change_stream *bcs = dev->sd_bcs;

    memset(status, 0, sizeof(*status));
    status->minor = dev->sd_minor;

    if (!bcs)
        return;

    spin_lock_irqsave(&bcs->lock, flags);
    status->last_changed_block = bcs->last_changed_block;
    status->last_changed_count = bcs->last_changed_count;
    status->last_recorded_jiffies = bcs->last_recorded_jiffies;
    status->captured_writes = bcs->captured_writes;
    status->captured_bytes = bcs->captured_bytes;
    status->changed_ranges = bcs->changed_ranges;
    status->changed_blocks = bcs->changed_blocks;
    status->cached_blocks = bcs->cached_blocks;
    status->complete_blocks = bcs->complete_blocks;
    status->partial_blocks = bcs->partial_blocks;
    status->ring_capacity = block_change_stream_ring_capacity(bcs->ring);
    status->ring_used = block_change_stream_ring_bytes_used(bcs->ring);
    if (bcs->ring) {
        status->ring_dropped_records = READ_ONCE(bcs->ring->dropped_records);
        status->ring_dropped_bytes = READ_ONCE(bcs->ring->dropped_bytes);
    }
    spin_unlock_irqrestore(&bcs->lock, flags);
}

ssize_t block_change_stream_read(struct snap_device *dev, char __user *buf, size_t length,
                                 int nonblock)
{
    struct block_change_stream *bcs;
    ssize_t ret;
    int fail_ret;

    if (!dev || !dev->sd_bcs)
        return -ENODEV;

    bcs = dev->sd_bcs;

    if (bcs->shutting_down)
        return -ENODEV;

    if (nonblock && !block_change_stream_ring_bytes_used(bcs->ring))
        return -EAGAIN;

    ret = wait_event_interruptible(bcs->read_wait,
                                   block_change_stream_ring_bytes_used(bcs->ring) > 0 ||
                                           tracer_read_fail_state(dev) || bcs->shutting_down);
    if (ret)
        return ret;

    fail_ret = tracer_read_fail_state(dev);
    if (bcs->shutting_down)
        return -ENODEV;
    if (fail_ret && !block_change_stream_ring_bytes_used(bcs->ring))
        return fail_ret;

    return block_change_stream_ring_read_user(bcs->ring, buf, length);
}

__poll_t block_change_stream_poll(struct snap_device *dev, struct file *file, poll_table *wait)
{
    struct block_change_stream *bcs;
    __poll_t mask = 0;

    if (!dev || !dev->sd_bcs)
        return POLLERR;

    bcs = dev->sd_bcs;
    poll_wait(file, &bcs->read_wait, wait);

    if (bcs->shutting_down)
        mask |= POLLHUP;
    if (block_change_stream_ring_bytes_used(bcs->ring) > 0)
        mask |= POLLIN | POLLRDNORM;
    if (tracer_read_fail_state(dev))
        mask |= POLLERR;

    return mask;
}
