// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "snap_handle.h"

#include "bio_helper.h"
#include "cow_manager.h"
#include "filesystem.h"
#include "logging.h"
#include "snap_device.h"

/* 快照 bio 操作模式宏 */
#define READ_MODE_COW_FILE 1
#define READ_MODE_BASE_DEVICE 2
#define READ_MODE_MIXED 3

#ifndef READ_SYNC
#define READ_SYNC 0
#endif

/**
 * snap_read_bio_get_mode() - 确定如何读取该 @bio。
 * @dev: &struct snap_device 对象指针。
 * @bio: 描述此次 I/O 的 &struct bio。
 * @mode: 输出计算得到的读模式。
 *
 * BIO 数据来源有三种：全部在 COW 缓存（READ_MODE_COW_FILE）、全部在块设备（READ_MODE_BASE_DEVICE）、
 * 或两者混合（READ_MODE_MIXED）。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
static int snap_read_bio_get_mode(const struct snap_device *dev, struct bio *bio, int *mode)
{
    int ret, start_mode = 0;
    bio_iter_t iter;
    bio_iter_bvec_t bvec;
    unsigned int bytes;
    uint64_t block_mapping, curr_byte, curr_end_byte = bio_sector(bio) * SECTOR_SIZE;

    bio_for_each_segment (bvec, bio, iter) {
        // 重置本 bio_vec 已遍历的字节数
        bytes = 0;

        while (bytes < bio_iter_len(bio, iter)) {
            // 确定下一段写的起止字节
            curr_byte = curr_end_byte;
            curr_end_byte += min(COW_BLOCK_SIZE - (curr_byte % COW_BLOCK_SIZE),
                                 ((uint64_t)bio_iter_len(bio, iter) - bytes));

            // 检查映射是否存在
            ret = cow_read_mapping(dev->sd_cow, curr_byte / COW_BLOCK_SIZE, &block_mapping);
            if (ret)
                goto error;

            if (!start_mode && block_mapping)
                start_mode = READ_MODE_COW_FILE;
            else if (!start_mode && !block_mapping)
                start_mode = READ_MODE_BASE_DEVICE;
            else if ((start_mode == READ_MODE_COW_FILE && !block_mapping) ||
                     (start_mode == READ_MODE_BASE_DEVICE && block_mapping)) {
                *mode = READ_MODE_MIXED;
                return 0;
            }

            bytes += curr_end_byte - curr_byte;
        }
    }

    *mode = start_mode;
    return 0;

error:
    LOG_ERROR(ret, "error finding read mode");
    return ret;
}

/**
 * snap_handle_read_bio() - 读取 @bio 中的全部数据；数据可能全在 COW 缓存、全在块设备或两者混合。
 * @dev: 保存快照设备状态的 &struct snap_device。
 * @bio: 描述此次 I/O 的 &struct bio。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
int snap_handle_read_bio(const struct snap_device *dev, struct bio *bio)
{
    int ret, mode;
    void *orig_private;
    bio_end_io_t *orig_end_io;
    char *data;
    sector_t bio_orig_sect, cur_block, cur_sect;
    unsigned int bio_orig_idx, bio_orig_size;
    uint64_t block_mapping, bytes_to_copy, block_off, bvec_off;
    struct bio_vec *bvec;

#ifdef HAVE_BVEC_ITER_ALL
    struct bvec_iter_all iter;
#else
    int i = 0;
#endif

    // 保存 bio 的原始状态
    orig_private = bio->bi_private;
    orig_end_io = bio->bi_end_io;
    bio_orig_idx = bio_idx(bio);
    bio_orig_size = bio_size(bio);
    bio_orig_sect = bio_sector(bio);

    dattobd_bio_set_dev(bio, dev->sd_base_dev->bdev);
    dattobd_set_bio_ops(bio, REQ_OP_READ, READ_SYNC);

    // 检测完全落在 COW 文件或基设备内的快速路径
    ret = snap_read_bio_get_mode(dev, bio, &mode);
    if (ret)
        goto out;

    // 将 bio 提交到基设备并等待完成
    if (mode != READ_MODE_COW_FILE) {
        ret = dattobd_submit_bio_wait(bio);
        if (ret) {
            LOG_ERROR(ret, "error reading from base device for read");
            goto out;
        }

#ifdef HAVE_BIO_BI_REMAINING
        //#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
        atomic_inc(&bio->bi_remaining);
#endif
    }

    // 从 COW 文件读取 bio 数据
    if (mode != READ_MODE_BASE_DEVICE) {
        // 恢复 bio 迭代状态
        bio_idx(bio) = bio_orig_idx;
        bio_size(bio) = bio_orig_size;
        bio_sector(bio) = bio_orig_sect;
        cur_sect = bio_sector(bio);

#ifdef HAVE_BVEC_ITER_ALL
        bio_for_each_segment_all (bvec, bio, iter) {
#else
        bio_for_each_segment_all (bvec, bio, i) {
#endif
            // 将页映射到内核空间
            data = kmap(bvec->bv_page);

            cur_block = (cur_sect * SECTOR_SIZE) / COW_BLOCK_SIZE;
            block_off = (cur_sect * SECTOR_SIZE) % COW_BLOCK_SIZE;
            bvec_off = bvec->bv_offset;

            while (bvec_off < bvec->bv_offset + bvec->bv_len) {
                bytes_to_copy =
                        min(bvec->bv_offset + bvec->bv_len - bvec_off, COW_BLOCK_SIZE - block_off);
                // 检查映射是否存在
                ret = cow_read_mapping(dev->sd_cow, cur_block, &block_mapping);
                if (ret) {
                    kunmap(bvec->bv_page);
                    goto out;
                }

                // 若映射存在则读入页并覆盖现场数据
                if (block_mapping) {
                    ret = cow_read_data(dev->sd_cow, data + bvec_off, block_mapping, block_off,
                                        bytes_to_copy);
                    if (ret) {
                        kunmap(bvec->bv_page);
                        goto out;
                    }
                }

                cur_sect += bytes_to_copy / SECTOR_SIZE;
                cur_block = (cur_sect * SECTOR_SIZE) / COW_BLOCK_SIZE;
                block_off = (cur_sect * SECTOR_SIZE) % COW_BLOCK_SIZE;
                bvec_off += bytes_to_copy;
            }

            // 解除页的内核映射
            kunmap(bvec->bv_page);
        }
    }

out:
    if (ret) {
        LOG_ERROR(ret, "error handling read bio");
        bio_idx(bio) = bio_orig_idx;
        bio_size(bio) = bio_orig_size;
        bio_sector(bio) = bio_orig_sect;
    }

    // 恢复 bio 的原始字段
    bio->bi_private = orig_private;
    bio->bi_end_io = orig_end_io;

    return ret;
}

/**
 * snap_handle_write_bio() - 将 BIO 中全部数据写入；在允许新数据写入前会先缓存/保存块设备上原有数据，
 *                           若原数据已保存则仅将新数据写入块设备。
 * @dev: 保存快照设备状态的 &struct snap_device。
 * @bio: 描述此次 I/O 的 &struct bio。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
int snap_handle_write_bio(const struct snap_device *dev, struct bio *bio)
{
    int ret;
    char *data;
    sector_t start_block, end_block = SECTOR_TO_BLOCK(bio_sector(bio));
    struct bio_vec *bvec;
#ifdef HAVE_BVEC_ITER_ALL
    struct bvec_iter_all iter;
#else
    int i = 0;
#endif

    // 遍历 bio 并处理每段（保证按块对齐）
    const unsigned long long number_of_blocks = bio_size(bio);
    unsigned long long saved_blocks = 0;

#ifdef HAVE_BVEC_ITER_ALL
    bio_for_each_segment_all (bvec, bio, iter) {
#else
    bio_for_each_segment_all (bvec, bio, i) {
#endif

        // 确定起止块
        start_block = end_block;
        end_block = start_block + bvec->bv_len / COW_BLOCK_SIZE;

        // 将页映射到内核空间
        data = kmap(bvec->bv_page);

        for (; start_block < end_block; start_block++) {
            // 将块交给 cow manager 处理
            ret = cow_write_current(dev->sd_cow, start_block, data);
            if (ret) {
                LOG_ERROR(ret, "memory demands %llu, memory saved before crash %llu",
                          number_of_blocks * COW_BLOCK_SIZE, saved_blocks * COW_BLOCK_SIZE);
                kunmap(bvec->bv_page);
                goto error;
            }
            saved_blocks++;
        }

        // 解除页映射
        kunmap(bvec->bv_page);
    }

    return 0;

error:
    LOG_ERROR(ret, "error handling write bio");
    return ret;
}

/**
 * inc_handle_sset() - 为覆盖该扇区范围的每个 COW 块在映射状态中加入占位。
 * @dev: 保存快照设备状态的 &struct snap_device。
 * @sset: 描述此次跨越扇区的 I/O 的 &struct sector_set。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int inc_handle_sset(const struct snap_device *dev, struct sector_set *sset)
{
    int ret;
    sector_t start_block = SECTOR_TO_BLOCK(sset->sect);
    sector_t end_block = NUM_SEGMENTS(sset->sect + sset->len, COW_BLOCK_LOG_SIZE - SECTOR_SHIFT);

    for (; start_block < end_block; start_block++) {
        ret = cow_write_filler_mapping(dev->sd_cow, start_block);
        if (ret)
            goto error;
    }

    return 0;

error:
    LOG_ERROR(ret, "error handling sset");
    return ret;
}
