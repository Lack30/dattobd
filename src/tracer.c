// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

#include "tracer.h"

#include "bio_request_callback.h"
#include "blkdev.h"
#include "callback_refs.h"
#include "cow_manager.h"
#include "filesystem.h"
#include "hints.h"
#include "logging.h"
#include "module_control.h"
#include "module_threads.h"
#include "mrf.h"
#include "snap_device.h"
#include "snap_ops.h"
#include "submit_bio.h"
#include "task_helper.h"
#include "tracer_helper.h"
#include "tracing_params.h"
#include <linux/blk-mq.h>
#include <linux/version.h>
#include "stack_limits.h"
#ifdef HAVE_BLK_ALLOC_QUEUE
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/percpu-refcount.h>
#endif

#if !defined(HAVE_BDEV_STACK_LIMITS) && !defined(HAVE_BLK_SET_DEFAULT_LIMITS)
// #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

#ifndef min_not_zero
#define min_not_zero(l, r) ((l) == 0) ? (r) : (((r) == 0) ? (l) : min(l, r))
#endif

int blk_stack_limits(struct queue_limits *t, struct queue_limits *b, sector_t offset)
{
    t->max_sectors = min_not_zero(t->max_sectors, b->max_sectors);
    t->max_hw_sectors = min_not_zero(t->max_hw_sectors, b->max_hw_sectors);
    t->bounce = min_not_zero(t->bounce, b->bounce);
    t->seg_boundary_mask = min_not_zero(t->seg_boundary_mask, b->seg_boundary_mask);
    t->max_segments = min_not_zero(t->max_segments, b->max_segments);
    t->max_segments = min_not_zero(t->max_segments, b->max_segments);
    t->max_segment_size = min_not_zero(t->max_segment_size, b->max_segment_size);
    return 0;
}

static int blk_stack_limits_request_queue(struct request_queue *t, struct request_queue *b,
                                          sector_t offset)
{
    return blk_stack_limits(&t->limits, &b->limits, 0);
}

static int dattobd_bdev_stack_limits(struct request_queue *t, struct block_device *bdev,
                                     sector_t start)
{
    struct request_queue *bq = bdev_get_queue(bdev);
    start += get_start_sect(bdev);
    return blk_stack_limits_request_queue(t, bq, start << 9);
}

#elif !defined(HAVE_BDEV_STACK_LIMITS)
// #elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
/* bdev_stack_limits 与 dattobd_bdev_stack_limits 由 stack_limits.h 提供 */
#else
#define dattobd_bdev_stack_limits(queue, bdev, start)                                              \
    bdev_stack_limits(&(queue)->limits, bdev, start)
#endif // # !HAVE_BDEV_STACK_LIMITS) && !HAVE_BLK_SET_DEFAULT_LIMITS

/* 获取/设置块设备的 make_request_fn 或 submit_bio 函数指针的辅助函数 */
static inline BIO_REQUEST_CALLBACK_FN *dattobd_get_bd_fn(struct block_device *bdev)
{
#ifdef USE_BDOPS_SUBMIT_BIO
    return bdev->bd_disk->fops->submit_bio;
#else
    return bdev->bd_disk->queue->make_request_fn;
#endif
}

#ifndef HAVE_BLK_SET_DEFAULT_LIMITS
#define blk_set_default_limits(ql)
#endif

#define __tracer_setup_cow_new(dev, bdev, cow_path, size, fallocated_space, cache_size, uuid,      \
                               seqid)                                                              \
    __tracer_setup_cow(dev, bdev, cow_path, size, fallocated_space, cache_size, uuid, seqid, 0)
#define __tracer_setup_cow_reload_snap(dev, bdev, cow_path, size, cache_size)                      \
    __tracer_setup_cow(dev, bdev, cow_path, size, 0, cache_size, NULL, 0, 1)
#define __tracer_setup_cow_reload_inc(dev, bdev, cow_path, size, cache_size)                       \
    __tracer_setup_cow(dev, bdev, cow_path, size, 0, cache_size, NULL, 0, 2)
#define __tracer_setup_cow_reopen(dev, bdev, cow_path)                                             \
    __tracer_setup_cow(dev, bdev, cow_path, 0, 0, 0, NULL, 0, 3)

#define __tracer_destroy_cow_free(dev) __tracer_destroy_cow(dev, 0)
#define __tracer_destroy_cow_sync_and_free(dev) __tracer_destroy_cow(dev, 1)
#define __tracer_destroy_cow_sync_and_close(dev) __tracer_destroy_cow(dev, 2)

#define __tracer_setup_inc_cow_thread(dev, minor) __tracer_setup_cow_thread(dev, minor, 0)
#define __tracer_setup_snap_cow_thread(dev, minor) __tracer_setup_cow_thread(dev, minor, 1)
#ifndef HAVE_BLK_SET_STACKING_LIMITS
#define blk_set_stacking_limits(ql) blk_set_default_limits(ql)
#endif

#ifdef HAVE_BIOSET_NEED_BVECS_FLAG
#define dattobd_bioset_create(bio_size, bvec_size, scale)                                          \
    bioset_create(bio_size, bvec_size, BIOSET_NEED_BVECS)
#elif defined HAVE_BIOSET_CREATE_3
#define dattobd_bioset_create(bio_size, bvec_size, scale) bioset_create(bio_size, bvec_size, scale)
#else
#define dattobd_bioset_create(bio_size, bvec_size, scale) bioset_create(bio_size, scale)
#endif

#define tracer_setup_unverified_inc(dev, minor, bdev_path, cow_path, cache_size, snap_devices)     \
    __tracer_setup_unverified(dev, minor, bdev_path, cow_path, cache_size, 0, snap_devices)
#define tracer_setup_unverified_snap(dev, minor, bdev_path, cow_path, cache_size, snap_devices)    \
    __tracer_setup_unverified(dev, minor, bdev_path, cow_path, cache_size, 1, snap_devices)

#define ROUND_UP(x, chunk) ((((x) + (chunk)-1) / (chunk)) * (chunk))
#define ROUND_DOWN(x, chunk) (((x) / (chunk)) * (chunk))

/* 扇区与块大小相关宏 */
#define SECTORS_PER_PAGE (PAGE_SIZE / SECTOR_SIZE)
#define BLOCK_TO_SECTOR(block) ((block)*SECTORS_PER_BLOCK)

void dattobd_free_request_tracking_ptr(struct snap_device *dev)
{
#ifdef USE_BDOPS_SUBMIT_BIO
    if (dev->sd_tracing_ops) {
        tracing_ops_put(dev->sd_tracing_ops);
        dev->sd_tracing_ops = NULL;
    }
#else
    dev->sd_orig_request_fn = NULL;
#endif
}

/**
 * snap_trace_bio() - 快照时跟踪 bio。读请求直接交给原驱动；写请求需先读原数据，
 *                   若一次读不完则多次创建 bio 直到处理完整个原 bio。
 *
 * @dev: 保存设备状态的 &struct snap_device。
 * @bio: 描述此次 I/O 的 &struct bio。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 错误
 */
static int snap_trace_bio(struct snap_device *dev, struct bio *bio)
{
    int ret;
    struct bio *new_bio = NULL;
    struct tracing_params *tp = NULL;
    sector_t start_sect, end_sect;
    unsigned int bytes, pages;

    // 若无需 COW 则直接调用真实 mrf
    if (!bio_needs_cow(bio, dev->sd_cow_inode) || tracer_read_fail_state(dev)) {
#ifdef HAVE_NONVOID_SUBMIT_BIO_1
        return SUBMIT_BIO_REAL(dev, bio);
#else
        SUBMIT_BIO_REAL(dev, bio);
        return 0;
#endif
    }

    // cow manager 按 4096 字节块工作，读克隆也须 4096 字节对齐
    start_sect =
            ROUND_DOWN(bio_sector(bio) - dev->sd_sect_off, SECTORS_PER_BLOCK) + dev->sd_sect_off;
    end_sect = ROUND_UP(bio_sector(bio) + (bio_size(bio) / SECTOR_SIZE) - dev->sd_sect_off,
                        SECTORS_PER_BLOCK) +
               dev->sd_sect_off;
    pages = (end_sect - start_sect) / SECTORS_PER_PAGE;
    if (pages < 1) {
        LOG_DEBUG("error tracing bio at page %d, submit bio directly", pages);
#ifdef HAVE_NONVOID_SUBMIT_BIO_1
        return SUBMIT_BIO_REAL(dev, bio);
#else
        SUBMIT_BIO_REAL(dev, bio);
        return 0;
#endif
    }

    // 分配 tracing_params 以在跨上下文中保存所需指针
    ret = tp_alloc(dev, bio, &tp);
    if (ret) {
        LOG_ERROR(ret, "error tracing bio for snapshot");
        tracer_set_fail_state(dev, ret);
#ifdef USE_BDOPS_SUBMIT_BIO
        goto error;
#else
        return SUBMIT_BIO_REAL(dev, bio);
#endif
    }

    while (1) {
        // 分配并填充读 bio 克隆；因队列限制可能无法包含全部所需页
        ret = bio_make_read_clone(dev_bioset(dev), tp, bio, start_sect, pages, &new_bio, &bytes);
        if (ret)
            goto error;

        // 为读克隆设置指针
        ret = tp_add(tp, new_bio);
        if (ret)
            goto error;

        atomic64_inc(&dev->sd_submitted_cnt);
        smp_wmb();

#ifdef USE_BDOPS_SUBMIT_BIO
        if (dev->sd_orig_request_fn) {
            SUBMIT_BIO_REAL(dev, new_bio);
        } else {
            dattobd_submit_bio(new_bio);
        }
#else
        dattobd_submit_bio(new_bio);
#endif

        // 若当前 bio 未覆盖整个克隆则继续创建 bio 直到覆盖完
        if (bytes / PAGE_SIZE < pages) {
            start_sect += bytes / SECTOR_SIZE;
            pages -= bytes / PAGE_SIZE;
            continue;
        }

        break;
    }

    // 释放对 tp 的引用
    tp_put(tp);

    return 0;

error:
    LOG_ERROR(ret, "error tracing bio for snapshot");
    tracer_set_fail_state(dev, ret);

    // 释放已分配但未提交的 bio
    if (new_bio)
        bio_free_clone(new_bio);

    if (tp)
        tp_put(tp);

    return 0;
}

/**
 * inc_make_sset() - 分配记录对象以保存本次调用传入的变更，并加入内核线程处理队列。
 *
 * @dev: 用于计算相对扇区偏移的 &struct snap_device。
 * @sect: 首个变更扇区的绝对偏移
 * @len: 变更长度（扇区数）
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int inc_make_sset(struct snap_device *dev, sector_t sect, unsigned int len)
{
    struct sector_set *sset;

    // 分配 sector set 记录变更扇区
    sset = kmalloc(sizeof(struct sector_set), GFP_NOIO);
    if (!sset) {
        LOG_ERROR(-ENOMEM, "error allocating sector set");
        return -ENOMEM;
    }

    sset->sect = sect - dev->sd_sect_off;
    sset->len = len;

    // 将 sset 入队由内核线程处理
    sset_queue_add(&dev->sd_pending_ssets, sset);

    return 0;
}

/**
 * inc_trace_bio() - 确定 @bio 修改的区域并排队记录，以便保存变更记录；随后由原始
 *                  I/O 提交函数（make_request_fn 或 submit_bio）处理该 bio 使修改落盘。
 *                  此模式只记录变更，不做 COW 数据。
 *
 * @dev: 保存设备状态的 &struct snap_device。
 * @bio: 描述此次 I/O 的 &struct bio。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int inc_trace_bio(struct snap_device *dev, struct bio *bio)
{
    int ret = 0, is_initialized = 0;
    sector_t start_sect = 0, end_sect = bio_sector(bio);
    bio_iter_t iter;
    bio_iter_bvec_t bvec;

#ifdef HAVE_ENUM_REQ_OPF
    //#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
    if (bio_op(bio) == REQ_OP_WRITE_ZEROES) {
        ret = inc_make_sset(dev, bio_sector(bio), bio_size(bio) / SECTOR_SIZE);
        goto out;
    }
#endif
    bio_for_each_segment (bvec, bio, iter) {
        if (page_get_inode(bio_iter_page(bio, iter)) != dev->sd_cow_inode) {
            if (!is_initialized) {
                is_initialized = 1;
                start_sect = end_sect;
            }
        } else {
            if (is_initialized && end_sect - start_sect > 0) {
                ret = inc_make_sset(dev, start_sect, end_sect - start_sect);
                if (ret)
                    goto out;
            }
            is_initialized = 0;
        }
        end_sect += (bio_iter_len(bio, iter) >> 9);
    }

    if (is_initialized && end_sect - start_sect > 0) {
        ret = inc_make_sset(dev, start_sect, end_sect - start_sect);
        if (ret)
            goto out;
    }

out:
    if (ret) {
        LOG_ERROR(ret, "error tracing bio for incremental");
        tracer_set_fail_state(dev, ret);
        ret = 0;
    }

    // 调用原始 mrf
    SUBMIT_BIO_REAL(dev, bio);

    return ret;
}

/**
 * bdev_is_already_traced() - 检查该 &struct block_device 是否已被本驱动跟踪。
 *
 * @bdev: 待检查的 &struct block_device。
 * @snap_devices: 快照设备数组。
 *
 * Return:
 * * 0 - 未被跟踪
 * * 1 - 已被跟踪
 */
static int bdev_is_already_traced(const struct block_device *bdev, snap_device_array snap_devices)
{
    int i;
    struct snap_device *dev;

    tracer_for_each(dev, i)
    {
        if (!dev || test_bit(UNVERIFIED, &dev->sd_state))
            continue;
        if (dev->sd_base_dev->bdev == bdev)
            return 1;
    }

    return 0;
}

/**
 * file_is_on_bdev() - 检查 dattobd 可变文件对象是否位于该块设备上。
 *
 * @dfilp: dattobd 可变文件对象。
 * @bdev: 可能包含 @dfilp 的 &struct block_device。
 *
 * Return:
 * * 0 - @dfilp 不在 @bdev 上
 * * !0 - @dfilp 在 @bdev 上
 */
static int file_is_on_bdev(const struct dattobd_mutable_file *dfilp, struct block_device *bdev)
{
    struct super_block *sb = dattobd_get_super(bdev);
    struct super_block *sb_file = dfilp->mnt->mnt_sb;
    int ret = 0;

    if (sb) {
        LOG_DEBUG("file_is_on_bdev() if(sb)");
        LOG_DEBUG("sb name:%s, file->sb name:%s", sb->s_root->d_name.name,
                  sb_file->s_root->d_name.name);
        ret = (dfilp->mnt->mnt_sb == sb);
        dattobd_drop_super(sb);
    }
    return ret;
}

/**
 * minor_range_recalculate() - 更新本驱动跟踪的次设备号范围，在某个 minor 不再使用时调用。
 *
 * @snap_devices: 快照设备数组。
 */
static void minor_range_recalculate(snap_device_array snap_devices)
{
    unsigned int i, highest = 0, lowest = dattobd_max_snap_devices - 1;
    struct snap_device *dev;

    tracer_for_each_full(dev, i)
    {
        if (!dev)
            continue;

        if (i < lowest)
            lowest = i;
        if (i > highest)
            highest = i;
    }

    lowest_minor = lowest;
    highest_minor = highest;
}

/**
 * minor_range_include() - 可能扩大本驱动跟踪的次设备号上下界。
 *
 * @minor: 设备次设备号
 */
static void minor_range_include(unsigned int minor)
{
    if (minor < lowest_minor)
        lowest_minor = minor;
    if (minor > highest_minor)
        highest_minor = minor;
}

/**
 * __tracer_init() - 初始化 &struct snap_device 对象。
 *
 * @dev: 用于跟踪快照设备变更的 &struct snap_device。
 */
static void __tracer_init(struct snap_device *dev)
{
    LOG_DEBUG("initializing tracer");
    atomic_set(&dev->sd_fail_code, 0);
    atomic_set(&dev->sd_active, 0);
    bio_queue_init(&dev->sd_cow_bios);
    bio_queue_init(&dev->sd_orig_bios);
    sset_queue_init(&dev->sd_pending_ssets);
}

/**
 * tracer_alloc() - 分配并初始化用于跟踪新快照设备变更的 &struct snap_device。
 *
 * @dev_ptr: 本调用分配得到的 &struct snap_device 指针。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int tracer_alloc(struct snap_device **dev_ptr)
{
    int ret;
    struct snap_device *dev;

    // 分配设备结构体
    LOG_DEBUG("allocating device struct");
    dev = kzalloc(sizeof(struct snap_device), GFP_KERNEL);
    if (!dev) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating memory for device struct");
        goto error;
    }

    __tracer_init(dev);

    *dev_ptr = dev;
    return 0;

error:
    LOG_ERROR(ret, "error allocating device struct");
    if (dev)
        kfree(dev);

    *dev_ptr = NULL;
    return ret;
}

/**
 * __tracer_destroy_cow() - 拆除 COW 跟踪状态并释放 &struct cow_manager。
 *
 * @dev: 保存快照设备状态的 &struct snap_device。
 * @close_method: 关闭方式。
 *                * 0: 释放内存并 unlink 后备文件。
 *                * 1: 刷写区段缓存、关闭 COW 文件、释放 &struct cow_manager。
 *                * 2: 刷写区段缓存、关闭 COW 文件。
 *                * 其他: 未定义。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __tracer_destroy_cow(struct snap_device *dev, int close_method)
{
    int ret = 0;

    dev->sd_cow_inode = NULL;
    dev->sd_falloc_size = 0;
    dev->sd_cache_size = 0;

    if (dev->sd_cow) {
        LOG_DEBUG("destroying cow manager");

        if (close_method == 0) {
            cow_free(dev->sd_cow);
            dev->sd_cow = NULL;
        } else if (close_method == 1) {
            ret = cow_sync_and_free(dev->sd_cow);
            dev->sd_cow = NULL;
        } else if (close_method == 2) {
            ret = cow_sync_and_close(dev->sd_cow);
            task_work_flush();
        }
    }

    if (close_method != 2 && dev->sd_cow_extents) {
        LOG_DEBUG("destroying cow file extents");
        kfree(dev->sd_cow_extents);
        dev->sd_cow_extents = NULL;
        dev->sd_cow_ext_cnt = 0;
        dev->sd_cow_inode = NULL;
    } else {
        LOG_DEBUG("preserving cow file extents");
    }

    dev->sd_falloc_size = 0;
    dev->sd_cache_size = 0;

    return ret;
}

/**
 * __tracer_setup_cow() - 设置 COW 跟踪相关结构。
 *
 * @dev: 保存快照设备状态的 &struct snap_device。
 * @bdev: 存放 COW 数据的 &struct block_device。
 * @cow_path: COW 后备文件路径。
 * @size: 为 COW 文件分配的扇区数。
 * @fallocated_space: 0 表示使用默认预分配大小。
 * @cache_size: COW 区段缓存大小上限（字节）。
 * @uuid: 该系列快照的 UUID，NULL 表示自动生成。
 * @seqid: 头部使用的当前序列 ID。
 * @open_method: 打开方式。决定 &struct cow_manager 及其缓存的处理方式：
 *               * 0: 创建并初始化新 COW 文件。
 *               * 3: 打开已有 COW 文件。
 *               * 其他: 重载 COW 管理器但不重载缓存。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __tracer_setup_cow(struct snap_device *dev, struct block_device *bdev,
                              const char *cow_path, sector_t size, unsigned long fallocated_space,
                              unsigned long cache_size, const uint8_t *uuid, uint64_t seqid,
                              int open_method)
{
    int ret;
    uint64_t max_file_size;

#ifdef HAVE_BDEVNAME
    char bdev_name[BDEVNAME_SIZE];
    bdevname(bdev, bdev_name);
    LOG_DEBUG("bdevname %s, cow_path: %s", bdev_name, cow_path);
#else
    LOG_DEBUG("bdevname %pg, cow_path: %s", bdev, cow_path);
#endif
    if (open_method == 3) {
        // 重新打开 cow manager
        LOG_DEBUG("reopening the cow manager with file '%s'", cow_path);
        ret = cow_reopen(dev->sd_cow, cow_path);
        if (ret)
            goto error;
    } else {
        if (!cache_size)
            dev->sd_cache_size = dattobd_cow_max_memory_default;
        else
            dev->sd_cache_size = cache_size;

        if (open_method == 0) {
            // 计算应为 COW 文件分配的空间
            if (!fallocated_space) {
                max_file_size = size * SECTOR_SIZE * dattobd_cow_fallocate_percentage_default;
                do_div(max_file_size, 100);
                dev->sd_falloc_size = max_file_size;
                do_div(dev->sd_falloc_size, (1024 * 1024));
            } else {
                max_file_size = fallocated_space * (1024 * 1024);
                dev->sd_falloc_size = fallocated_space;
            }

            // 创建并打开 cow manager
            LOG_DEBUG("creating cow manager");
            ret = cow_init(dev, cow_path, SECTOR_TO_BLOCK(size), COW_SECTION_SIZE,
                           dev->sd_cache_size, max_file_size, uuid, seqid, &dev->sd_cow);
            if (ret)
                goto error;
        } else {
            // 重载 cow manager
            LOG_DEBUG("reloading cow manager");
            ret = cow_reload(cow_path, SECTOR_TO_BLOCK(size), COW_SECTION_SIZE, dev->sd_cache_size,
                             (open_method == 2), &dev->sd_cow);
            if (ret)
                goto error;

            dev->sd_falloc_size = dev->sd_cow->file_size;
            do_div(dev->sd_falloc_size, (1024 * 1024));
        }
    }

    // 确认文件位于块设备上
    // 	if (!file_is_on_bdev(dev->sd_cow->dfilp, bdev)) {
    // 		ret = -EINVAL;
    // #ifdef HAVE_BDEVNAME
    // 		LOG_ERROR(ret, "'%s' is not on '%s'", cow_path, bdev_name);
    // #else
    // 		LOG_ERROR(ret, "'%s' is not on '%pg'", cow_path, bdev);
    // #endif
    // 		goto error;
    // 	}

    // 获取 COW 文件的 inode 号
    LOG_DEBUG("finding cow file inode");
    dev->sd_cow_inode = dev->sd_cow->dfilp->inode;

    return 0;

error:
    LOG_ERROR(ret, "error setting up cow manager");
    if (open_method != 3)
        __tracer_destroy_cow_free(dev);
    return ret;
}

/**
 * __tracer_destroy_base_dev() - 拆除底层块设备相关状态。
 *
 * @dev: &struct snap_device 对象指针。
 */
static void __tracer_destroy_base_dev(struct snap_device *dev)
{
    dev->sd_size = 0;
    dev->sd_sect_off = 0;

    if (dev->sd_bdev_path) {
        LOG_DEBUG("freeing base block device path");
        kfree(dev->sd_bdev_path);
        dev->sd_bdev_path = NULL;
    }

    if (dev->sd_base_dev) {
        LOG_DEBUG("freeing base block device");
        dattobd_blkdev_put(dev->sd_base_dev);
        dev->sd_base_dev = NULL;
    }
}

/**
 * __tracer_setup_base_dev() - 设置底层块设备。
 *
 * @dev: &struct snap_device 对象指针。
 * @bdev_path: 块设备路径，如 '/dev/loop0'。
 * @snap_devices: 快照设备数组。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __tracer_setup_base_dev(struct snap_device *dev, const char *bdev_path,
                                   snap_device_array snap_devices)
{
    int ret;

    // 打开基块设备
    LOG_DEBUG("ENTER __tracer_setup_base_dev");
    dev->sd_base_dev = dattobd_blkdev_by_path(bdev_path, FMODE_READ, NULL);
    if (IS_ERR(dev->sd_base_dev)) {
        ret = PTR_ERR(dev->sd_base_dev);
        dev->sd_base_dev = NULL;
        LOG_ERROR(ret, "error finding block device '%s'", bdev_path);
        goto error;
    } else if (!dev->sd_base_dev->bdev->bd_disk) {
        ret = -EFAULT;
        LOG_ERROR(ret, "error finding block device gendisk");
        goto error;
    }

    // 检查块设备未被跟踪
    LOG_DEBUG("checking block device is not already being traced");
    if (bdev_is_already_traced(dev->sd_base_dev->bdev, snap_devices)) {
        ret = -EINVAL;
        LOG_ERROR(ret, "block device is already being traced");
        goto error;
    }

    // 获取基设备的绝对路径
    LOG_DEBUG("fetching the absolute pathname for the base device");
    ret = pathname_to_absolute(bdev_path, &dev->sd_bdev_path, NULL);
    if (ret)
        goto error;

    // 若设备为分区则计算大小与偏移
    LOG_DEBUG("calculating block device size and offset");
    if (bdev_whole(dev->sd_base_dev->bdev) != dev->sd_base_dev->bdev) {
        dev->sd_sect_off = get_start_sect(dev->sd_base_dev->bdev);
        dev->sd_size = dattobd_bdev_size(dev->sd_base_dev->bdev);
    } else {
        dev->sd_sect_off = 0;
        dev->sd_size = get_capacity(dev->sd_base_dev->bdev->bd_disk);
    }

    LOG_DEBUG("bdev size = %llu, offset = %llu", (unsigned long long)dev->sd_size,
              (unsigned long long)dev->sd_sect_off);

    return 0;

error:
    LOG_ERROR(ret, "error setting up base block device");
    __tracer_destroy_base_dev(dev);
    return ret;
}

/**
 * __tracer_copy_base_dev() - 将底层块设备相关字段从 @src 复制到 @dest。
 *
 * @src: 源 &struct snap_device 对象指针。
 * @dest: 目标 &struct snap_device 对象指针。
 */
static void __tracer_copy_base_dev(const struct snap_device *src, struct snap_device *dest)
{
    dest->sd_size = src->sd_size;
    dest->sd_sect_off = src->sd_sect_off;
    dest->sd_base_dev = src->sd_base_dev;
    dest->sd_bdev_path = src->sd_bdev_path;
}

#ifdef HAVE_MERGE_BVEC_FN
#ifdef HAVE_BVEC_MERGE_DATA

/**
 * snap_merge_bvec() - 判断是否能在现有请求上追加更多数据；请求队列通常有固定大小
 *                    限制，专用设备可有不同限制。
 *
 * @q: &struct request_queue 对象指针。
 * @bvm: 传入 merge_bvec_fn() 的 &struct bvec_merge_data。
 * @bvec: 传入 merge_bvec_fn() 的 &struct bio_vec。
 *
 * Return: 底层函数返回值。
 */
static int snap_merge_bvec(struct request_queue *q, struct bvec_merge_data *bvm,
                           struct bio_vec *bvec)
{
    struct snap_device *dev = q->queuedata;
    struct request_queue *base_queue = bdev_get_queue(dev->sd_base_dev->bdev);

    bvm->bi_bdev = dev->sd_base_dev->bdev;

    return base_queue->merge_bvec_fn(base_queue, bvm, bvec);
}

#else

/**
 * snap_merge_bvec() - 判断是否能在现有请求上追加更多数据；请求队列通常有固定大小
 *                    限制，专用设备可有不同限制。
 *
 * @q: &struct request_queue 对象指针。
 * @bio_bvm: 传入 merge_bvec_fn() 的 &struct bio（bvec_merge_data）。
 * @bvec: 传入 merge_bvec_fn() 的 &struct bio_vec。
 *
 * Return: 底层函数返回值。
 */
static int snap_merge_bvec(struct request_queue *q, struct bio *bio_bvm, struct bio_vec *bvec)
{
    struct snap_device *dev = q->queuedata;
    struct request_queue *base_queue = bdev_get_queue(dev->sd_base_dev->bdev);

    bio_bvm->bi_bdev = dev->sd_base_dev->bdev;

    return base_queue->merge_bvec_fn(base_queue, bio_bvm, bvec);
}
#endif
#endif

/**
 * __tracer_copy_cow() - 将 COW 相关字段从 @src 复制到 @dest。
 *
 * @src: 源 &struct snap_device 对象指针。
 * @dest: 目标 &struct snap_device 对象指针。
 */
static void __tracer_copy_cow(const struct snap_device *src, struct snap_device *dest)
{
    dest->sd_cow = src->sd_cow;
    // 拷贝 COW 文件区段并更新设备
    dest->sd_cow_extents = src->sd_cow_extents;
    dest->sd_cow_ext_cnt = src->sd_cow_ext_cnt;
    dest->sd_cow_inode = src->sd_cow_inode;
    dest->sd_cow->dev = dest;

    dest->sd_cache_size = src->sd_cache_size;
    dest->sd_falloc_size = src->sd_falloc_size;
}

/**
 * __tracer_destroy_cow_path() - 释放 COW 路径相关资源。
 *
 * @dev: &struct snap_device 对象指针。
 */
static void __tracer_destroy_cow_path(struct snap_device *dev)
{
    if (dev->sd_cow_path) {
        LOG_DEBUG("freeing cow path");
        kfree(dev->sd_cow_path);
        dev->sd_cow_path = NULL;
    }
}

/**
 * __tracer_setup_cow_path() - 根据 &struct file 设置 COW 文件路径。
 *
 * @dev: &struct snap_device 对象指针。
 * @cow_dfile: &struct dattobd_mutable_file 对象指针。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __tracer_setup_cow_path(struct snap_device *dev,
                                   const struct dattobd_mutable_file *cow_dfile)
{
    int ret;

    // 获取 COW 文件路径（相对于挂载点）
    LOG_DEBUG("getting relative pathname of cow file");
    ret = dentry_get_relative_pathname(cow_dfile->dentry, &dev->sd_cow_path, NULL);
    if (ret)
        goto error;

    return 0;

error:
    LOG_ERROR(ret, "error setting up cow file path");
    __tracer_destroy_cow_path(dev);
    return ret;
}

/**
 * __tracer_copy_cow_path() - 从源设备复制 COW 文件路径到目标设备。
 *
 * @src: 源 &struct snap_device 对象指针。
 * @dest: 目标 &struct snap_device 对象指针。
 */
static void __tracer_copy_cow_path(const struct snap_device *src, struct snap_device *dest)
{
    dest->sd_cow_path = src->sd_cow_path;
}

/**
 * __tracer_bioset_exit() - 释放 &struct snap_device 内的 bioset。
 *
 * @dev: &struct snap_device 对象指针。
 */
static void __tracer_bioset_exit(struct snap_device *dev)
{
#ifndef HAVE_BIOSET_INIT
    //#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
    if (dev->sd_bioset) {
        LOG_DEBUG("freeing bio set");
        bioset_free(dev->sd_bioset);
        dev->sd_bioset = NULL;
    }
#else
    bioset_exit(&dev->sd_bioset);
#endif
}

/**
 * __tracer_destroy_snap() - 拆除快照设备。
 *
 * @dev: &struct snap_device 对象指针。
 */
static void __tracer_destroy_snap(struct snap_device *dev)
{
    LOG_DEBUG("tracer_destroy_snap");
    if (dev->sd_mrf_thread) {
        LOG_DEBUG("stopping mrf thread");
        kthread_stop(dev->sd_mrf_thread);
        dev->sd_mrf_thread = NULL;
    }

    if (dev->sd_gd) {
        LOG_DEBUG("freeing gendisk");
#ifdef GENHD_FL_UP
        if (dev->sd_gd->flags & GENHD_FL_UP)
#else
        if (disk_live(dev->sd_gd))
#endif
            del_gendisk(dev->sd_gd);
        put_disk(dev->sd_gd);
        dev->sd_gd = NULL;
    }

    if (dev->sd_queue) {
        LOG_DEBUG("freeing request queue");
#ifdef HAVE_BLK_CLEANUP_QUEUE
        blk_cleanup_queue(dev->sd_queue);
#else
#ifndef HAVE_BD_HAS_SUBMIT_BIO
        blk_put_queue(dev->sd_queue);
#endif
#endif
        dev->sd_queue = NULL;
    }

    __tracer_bioset_exit(dev);
}

/**
 * __tracer_bioset_init() - 初始化 &struct snap_device 的 bioset 字段。
 *
 * @dev: &struct snap_device 对象指针。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __tracer_bioset_init(struct snap_device *dev)
{
#ifndef HAVE_BIOSET_INIT
    //#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
    dev->sd_bioset = dattobd_bioset_create(BIO_SET_SIZE, BIO_SET_SIZE, 0);
    if (!dev->sd_bioset)
        return -ENOMEM;
    return 0;
#else
    return bioset_init(&dev->sd_bioset, BIO_SET_SIZE, BIO_SET_SIZE, BIOSET_NEED_BVECS);
#endif
}

/**
 * __tracer_setup_snap() - 为活动快照分配 &struct snap_device 字段，并设置用于呈现
 *                         底层在线卷快照镜像的只读磁盘、向内核注册。
 *
 * @dev: &struct snap_device 对象指针。
 * @minor: 设备次设备号。
 * @bdev: 存放 COW 数据的 &struct block_device。
 * @size: 为块设备分配的扇区数。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __tracer_setup_snap(struct snap_device *dev, unsigned int minor,
                               struct block_device *bdev, sector_t size)
{
    int ret;

    ret = __tracer_bioset_init(dev);
    if (ret) {
        LOG_ERROR(ret, "error initializing bio set");
        goto error;
    }

    // 分配 gendisk 结构体
    LOG_DEBUG("allocating gendisk");

#ifdef HAVE_BLK_ALLOC_DISK
    dev->sd_gd = blk_alloc_disk(NUMA_NO_NODE);
#else
    dev->sd_gd = alloc_disk(1);
#endif

    if (!dev->sd_gd) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating gendisk");
        goto error;
    }

    LOG_DEBUG("allocating queue");
#if defined HAVE_BDOPS_SUBMIT_BIO

#if defined HAVE_BLK_ALLOC_DISK
    dev->sd_queue = dev->sd_gd->queue;
#else // works until 6.9
    dev->sd_queue = blk_alloc_queue(NUMA_NO_NODE);
#endif /*HAVE_BLK_ALLOC_DISK*/

#else

#if defined HAVE_BLK_ALLOC_QUEUE_2
    dev->sd_queue = blk_alloc_queue(snap_mrf, NUMA_NO_NODE);
#elif defined HAVE_BLK_ALLOC_QUEUE_RH_2
    dev->sd_queue = blk_alloc_queue_rh(snap_mrf, NUMA_NO_NODE);
#else
    dev->sd_queue = blk_alloc_queue(GFP_KERNEL);

    if (dev->sd_queue != NULL) {
        LOG_DEBUG("setting up make request function");
        blk_queue_make_request(dev->sd_queue, snap_mrf);
    }
#endif /*HAVE_BLK_ALLOC_QUEUE_2*/

#endif /*HAVE_BDOPS_SUBMIT_BIO*/

    if (!dev->sd_queue) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating request queue");
        goto error;
    }

#if defined HAVE_GD_OWNS_QUEUE
    set_bit(GD_OWNS_QUEUE, &dev->sd_gd->state);
#endif
    // 使请求队列与基设备属性一致
    LOG_DEBUG("setting queue limits");
    blk_set_stacking_limits(&dev->sd_queue->limits);
    dattobd_bdev_stack_limits(dev->sd_queue, bdev, 0);

#ifdef HAVE_MERGE_BVEC_FN
    // 使用基设备 merge_bvec_fn 的薄封装
    if (bdev_get_queue(bdev)->merge_bvec_fn)
        blk_queue_merge_bvec(dev->sd_queue, snap_merge_bvec);
#endif

    // 初始化 gendisk 与请求队列字段
    LOG_DEBUG("initializing gendisk");
    dev->sd_queue->queuedata = dev;
    dev->sd_gd->private_data = dev;
    dev->sd_gd->major = major;
    dev->sd_gd->first_minor = minor;
    dev->sd_gd->minors = 1;
    dev->sd_gd->fops = get_snap_ops();
    dev->sd_gd->queue = dev->sd_queue;

    // 设置 gendisk 名称
    LOG_DEBUG("naming gendisk");
    snprintf(dev->sd_gd->disk_name, 32, SNAP_DEVICE_NAME, minor);

    // 设置 gendisk 容量
    LOG_DEBUG("block device size: %llu", (unsigned long long)size);
    set_capacity(dev->sd_gd, size);

#ifdef HAVE_GENHD_FL_NO_PART_SCAN
    //#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
    // 禁用分区扫描（本设备不应有子分区）
    dev->sd_gd->flags |= GENHD_FL_NO_PART_SCAN;
#elif defined HAVE_GENHD_FL_NO_PART
    // 内核去掉 genhd.h 后常量由 GENHD_FL_NO_PART_SCAN 改为 GENHD_FL_NO_PART
    dev->sd_gd->flags |= GENHD_FL_NO_PART;
#endif

    // 将设备设为只读
    set_disk_ro(dev->sd_gd, 1);

    atomic64_set(&dev->sd_submitted_cnt, 0);
    atomic64_set(&dev->sd_received_cnt, 0);

    LOG_DEBUG("starting mrf kernel thread");
    dev->sd_mrf_thread = kthread_run(snap_mrf_thread, dev, SNAP_MRF_THREAD_NAME_FMT, minor);
    if (IS_ERR(dev->sd_mrf_thread)) {
        ret = PTR_ERR(dev->sd_mrf_thread);
        dev->sd_mrf_thread = NULL;
        LOG_ERROR(ret, "error starting mrf kernel thread");
        goto error;
    }

    // 向内核注册 gendisk
    LOG_DEBUG("adding disk");
#ifdef HAVE_NONVOID_ADD_DISK
    ret = add_disk(dev->sd_gd);
    if (ret) {
        LOG_ERROR(ret, "error creating snapshot disk");
        goto error;
    }
#else
    add_disk(dev->sd_gd);
#endif
    return 0;

error:
    LOG_ERROR(ret, "error setting up snapshot");
    __tracer_destroy_snap(dev);
    return ret;
}

/**
 * __tracer_destroy_cow_thread() - 停止并释放 COW 线程。
 *
 * @dev: &struct snap_device 对象指针。
 */
static void __tracer_destroy_cow_thread(struct snap_device *dev)
{
    if (dev->sd_cow_thread) {
        LOG_DEBUG("stopping cow thread");
        kthread_stop(dev->sd_cow_thread);
        dev->sd_cow_thread = NULL;
    }
}

/**
 * __tracer_setup_cow_thread() - 创建 COW 线程并关联到 &struct snap_device。
 *
 * @dev: &struct snap_device 对象指针。
 * @minor: 设备次设备号。
 * @is_snap: 1 为快照，0 为增量。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __tracer_setup_cow_thread(struct snap_device *dev, unsigned int minor, int is_snap)
{
    int ret;

    LOG_DEBUG("creating kernel cow thread");
    if (is_snap)
        dev->sd_cow_thread = kthread_create(snap_cow_thread, dev, SNAP_COW_THREAD_NAME_FMT, minor);
    else
        dev->sd_cow_thread = kthread_create(inc_sset_thread, dev, INC_THREAD_NAME_FMT, minor);

    if (IS_ERR(dev->sd_cow_thread)) {
        ret = PTR_ERR(dev->sd_cow_thread);
        dev->sd_cow_thread = NULL;
        LOG_ERROR(ret, "error creating kernel thread");
        goto error;
    }

    return 0;

error:
    LOG_ERROR(ret, "error setting up cow thread");
    __tracer_destroy_cow_thread(dev);
    return ret;
}

/**
 * __tracer_transition_tracing() - 根据 @dev 是否定义在 @bdev 上启动或结束跟踪；
 *                                 转换期间会冻结 @bdev 再解冻，以便请求可重新挂到 @bdev。
 *
 * @dev: &struct snap_device 对象指针。
 * @bdev: 存放 COW 数据的 &struct block_device。
 * @new_bio_tracking_ptr: 快照盘 I/O 处理用可选函数指针，NULL 表示继续使用当前指针。
 * @dev_ptr: 成功时输出 &struct snap_device。
 * @start_tracing: 为 true 表示启动跟踪，为 false 表示结束跟踪。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
#ifndef USE_BDOPS_SUBMIT_BIO
static int __tracer_transition_tracing(struct snap_device *dev, struct block_device *bdev,
                                       BIO_REQUEST_CALLBACK_FN *new_bio_tracking_ptr,
                                       struct snap_device **dev_ptr, bool start_tracing)
#else
static int __tracer_transition_tracing(struct snap_device *dev, struct block_device *bdev,
                                       const struct block_device_operations *bd_ops,
                                       struct snap_device **dev_ptr, bool start_tracing)
#endif
{
    int ret;
    struct super_block *origsb = dattobd_get_super(bdev);
#ifdef HAVE_FREEZE_SB
    struct super_block *sb = NULL;
#endif

#ifdef HAVE_BDEVNAME
    char bdev_name[BDEVNAME_SIZE];
    bdevname(bdev, bdev_name);
#endif
    MAYBE_UNUSED(ret);
    if (origsb) {
        dattobd_drop_super(origsb);

        // 冻结并同步块设备
#ifdef HAVE_BDEVNAME
        LOG_DEBUG("freezing '%s'", bdev_name);
#else
        LOG_DEBUG("freezing '%pg'", bdev);
#endif
#ifdef HAVE_FREEZE_SB
        // #if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
        sb = freeze_bdev(bdev);
        if (!sb) {
#ifdef HAVE_BDEVNAME
            LOG_ERROR(-EFAULT, "error freezing '%s': null", bdev_name);
#else
            LOG_ERROR(-EFAULT, "error freezing '%pg': null", bdev);
#endif
            return -EFAULT;
        } else if (IS_ERR(sb)) {
#ifdef HAVE_BDEVNAME
            LOG_ERROR((int)PTR_ERR(sb), "error freezing '%s': error", bdev_name);
#else
            LOG_ERROR((int)PTR_ERR(sb), "error freezing '%pg': error", bdev);
#endif
            return (int)PTR_ERR(sb);
        }
#elif defined HAVE_BDEV_FREEZE
        ret = bdev_freeze(bdev);
#else
        ret = freeze_bdev(bdev);
        if (ret) {
#ifdef HAVE_BDEVNAME
            LOG_ERROR(ret, "error freezing '%s'", bdev_name);
#else
            LOG_ERROR(ret, "error freezing '%pg'", bdev);
#endif
            return -ret;
        }
#endif
    } else {
#ifdef HAVE_BDEVNAME
        LOG_WARN("warning: no super found for device '%s', unable to freeze it", bdev_name);
#endif
    }
    smp_wmb();
    if (start_tracing) {
        LOG_DEBUG("starting tracing");
        *dev_ptr = dev;
        smp_wmb();
#ifndef USE_BDOPS_SUBMIT_BIO
        if (new_bio_tracking_ptr) {
            bdev->bd_disk->queue->make_request_fn = new_bio_tracking_ptr;
        }
#else
        if (bd_ops) {
            bdev->bd_disk->fops = bd_ops;
        }
#ifdef HAVE_BD_HAS_SUBMIT_BIO
        bdev->bd_has_submit_bio = true;
#endif
#endif
        atomic_inc(&(*dev_ptr)->sd_active);
        smp_wmb();
    } else {
        LOG_DEBUG("ending tracing");
        atomic_dec(&(*dev_ptr)->sd_active);
#ifndef USE_BDOPS_SUBMIT_BIO
        new_bio_tracking_ptr = mrf_put(bdev->bd_disk);
        if (new_bio_tracking_ptr) {
            bdev->bd_disk->queue->make_request_fn = new_bio_tracking_ptr;
        }
#else
        if (bd_ops) {
            bdev->bd_disk->fops = bd_ops;
        }
#ifdef HAVE_BD_HAS_SUBMIT_BIO
        bdev->bd_has_submit_bio = dev->sd_tracing_ops->has_submit_bio;
#endif
#endif
        *dev_ptr = NULL;
        smp_wmb();
    }
    if (origsb) {
        // 解冻块设备
#ifdef HAVE_BDEVNAME
        LOG_DEBUG("thawing '%s'", bdev_name);
#else
        LOG_DEBUG("thawing '%pg'", bdev);
#endif
#ifdef HAVE_THAW_BDEV_INT
        ret = thaw_bdev(bdev, sb);
#elif defined HAVE_BDEV_THAW
        ret = bdev_thaw(bdev);
#else
        ret = thaw_bdev(bdev);
#endif
        if (ret) {
#ifdef HAVE_BEDVNAME
            LOG_ERROR(ret, "error thawing '%s'", bdev_name);
#else
            LOG_ERROR(ret, "error thawing '%pg'", bdev);
#endif
            // 此处无法合理回滚且已替换 mrf，假装成功以免破坏块设备
        }
    }
    return 0;
}

/**
 * tracing_fn() - 被拦截的在途 I/O 的入口。
 * @q: &struct request_queue。
 * @bio: 描述此次 I/O 的 &struct bio。
 *
 * 若 BIO 已标记为透传，则使用块设备原有的 I/O 处理函数处理；否则根据当前处于
 * 快照或增量模式调用相应处理函数。
 *
 * Return: 随 Linux 版本不同而不同，为各版本对 make request 函数的预期返回值。
 */
#ifdef USE_BDOPS_SUBMIT_BIO
static asmlinkage MRF_RETURN_TYPE tracing_fn(struct bio *bio)
#else
static MRF_RETURN_TYPE tracing_fn(struct request_queue *q, struct bio *bio)
#endif
{
    int i, ret = 0;
    struct snap_device *dev = NULL;
    make_request_fn *orig_fn = NULL;
    snap_device_array snap_devices = get_snap_device_array_nolock();
    MAYBE_UNUSED(ret);

    smp_rmb();
    tracer_for_each(dev, i)
    {
        if (!tracer_is_bio_for_dev(dev, bio))
            continue;
        // 能执行到此说明是本驱动管理的设备且当前 bio 属于该设备
        orig_fn = dev->sd_orig_request_fn;
        if (dattobd_bio_op_flagged(bio, DATTOBD_PASSTHROUGH)) {
            dattobd_bio_op_clear_flag(bio, DATTOBD_PASSTHROUGH);
        } else {
            if (tracer_should_trace_bio(dev, bio)) {
                if (test_bit(SNAPSHOT, &dev->sd_state))
                    ret = snap_trace_bio(dev, bio);
                else
                    ret = inc_trace_bio(dev, bio);
                goto out;
            }
        }
    } // tracer_for_each(dev, i)

#ifdef USE_BDOPS_SUBMIT_BIO
    if (unlikely(orig_fn == NULL)) {
        tracer_for_each(dev, i)
        {
            if (!tracer_is_bio_for_dev_only_queue(dev, bio))
                continue;
            orig_fn = dev->sd_orig_request_fn;
            if (orig_fn != NULL)
                break;
        }
    }
    if (orig_fn) {
        // LOG_DEBUG("found original mrf");
        orig_fn(bio);
    } else if (dattobd_bio_bi_disk(bio)->fops->submit_bio) {
        if (dattobd_bio_bi_disk(bio)->fops->submit_bio == tracing_fn) {
            LOG_DEBUG("dattobd snap null mrf");
            dattobd_snap_null_mrf(bio);
        } else {
            LOG_DEBUG("dattobd submit bio");
            dattobd_bio_bi_disk(bio)->fops->submit_bio(bio);
        }
    } else {
        LOG_DEBUG("dattobd submit_bio_noacct");
        submit_bio_noacct(bio);
    }
#else
    tracer_for_each(dev, i)
    {
        if (!tracer_is_bio_for_dev_only_queue(dev, bio))
            continue;
        ret = SUBMIT_BIO_REAL(dev, bio);
        goto out;
    }
    LOG_WARN("caught bio without original mrf to pass!");
#endif

out:
    put_snap_device_array_nolock(snap_devices);
    MRF_RETURN(ret);
}

#ifndef USE_BDOPS_SUBMIT_BIO

/**
 * dattobd_find_orig_mrf() - 查找与 @bdev 关联的原始 MRF 函数；会遍历所有被跟踪
 *                           的块设备直到找到匹配。
 *
 * @bdev: 存放 COW 数据的 &struct block_device。
 * @mrf: 找到的原始 MRF 函数指针。
 * @snap_devices: 快照设备数组。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int dattobd_find_orig_mrf(struct block_device *bdev, make_request_fn **mrf,
                                 snap_device_array snap_devices)
{
    int i;
    struct snap_device *dev;
    struct request_queue *q = bdev_get_queue(bdev);
    make_request_fn *orig_mrf = dattobd_get_bd_mrf(bdev);

    if (orig_mrf != tracing_fn) {
#ifdef HAVE_BLK_MQ_MAKE_REQUEST
        // 内核 5.8
        if (!orig_mrf) {
            orig_mrf = dattobd_null_mrf;
            LOG_DEBUG("original mrf is empty, set to dattobd_null_mrf");
        }
#endif
        *mrf = orig_mrf;
        return 0;
    }

    tracer_for_each(dev, i)
    {
        if (!dev || test_bit(UNVERIFIED, &dev->sd_state))
            continue;
        if (q == bdev_get_queue(dev->sd_base_dev->bdev)) {
            *mrf = dev->sd_orig_request_fn;
            return 0;
        }
    }

    *mrf = NULL;
    return -EFAULT;
}
#else
int find_orig_bdops(struct block_device *bdev, struct block_device_operations **ops,
                    make_request_fn **mrf, struct tracing_ops **trops,
                    snap_device_array snap_devices)
{
    int i;
    struct snap_device *dev;
    struct block_device_operations *orig_ops = dattobd_get_bd_ops(bdev);
    make_request_fn *orig_mrf = orig_ops->submit_bio;
    LOG_DEBUG("ENTER find_orig_bdops");
    *trops = NULL;

    if (orig_mrf != tracing_fn) {
        if (!orig_mrf) {
            LOG_DEBUG("original mrf is empty, setting it to dattobd_snap_null_mrf");
            // 后续可改为 mq 接口
            orig_mrf = dattobd_snap_null_mrf;
        } else {
            LOG_DEBUG("original mrf is not empt orig_mrf= %p, orig ops=%p", orig_mrf, orig_ops);
        }

        *ops = orig_ops;
        *mrf = orig_mrf;
        return 0;

    } else {
        LOG_DEBUG("original make request function is already replaced with tracing_fn");
    }

    tracer_for_each(dev, i)
    {
        if (!dev || test_bit(UNVERIFIED, &dev->sd_state))
            continue;
        if (orig_ops == dattobd_get_bd_ops(dev->sd_base_dev->bdev)) {
            *ops = dev->bd_ops;
            *mrf = dev->sd_orig_request_fn;
            *trops = tracing_ops_get(dev->sd_tracing_ops);
            LOG_DEBUG("found already tracked device with the same original bd_ops");
            return 0;
        }
    }

    *ops = NULL;
    *mrf = NULL;
    return -EFAULT;
}

int tracer_alloc_ops(struct snap_device *dev)
{
    struct tracing_ops *trops;
    trops = kmalloc(sizeof(struct tracing_ops), GFP_KERNEL);

    LOG_DEBUG("%s", __func__);
    if (!trops) {
        LOG_ERROR(-ENOMEM, "error allocating tracing ops struct");
        return -ENOMEM;
    }

    trops->bd_ops = kmalloc(sizeof(struct block_device_operations), GFP_KERNEL);
    if (!trops->bd_ops) {
        kfree(trops);
        LOG_ERROR(-ENOMEM, "error while alocating new block_device_operations");
        return -ENOMEM;
    }
    memcpy(trops->bd_ops, dattobd_get_bd_ops(dev->sd_base_dev->bdev),
           sizeof(struct block_device_operations));
    trops->bd_ops->submit_bio = tracing_fn;
#ifdef HAVE_BD_HAS_SUBMIT_BIO
    trops->has_submit_bio = dev->sd_base_dev->bdev->bd_has_submit_bio;
#endif
    atomic_set(&trops->refs, 1);
    dev->sd_tracing_ops = trops;
    return 0;
}

#endif

/**
 * __tracer_should_reset_mrf() - 在已跟踪设备中查找，确认该设备在开始跟踪时具有
 *                               make_request_fn。
 * @dev: &struct snap_device 对象指针。
 * @snap_devices: 快照设备数组。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __tracer_should_reset_mrf(const struct snap_device *dev, snap_device_array snap_devices)
{
        int i;
        struct snap_device *cur_dev;
        struct request_queue *q = bdev_get_queue(dev->sd_base_dev->bdev);
#ifdef USE_BDOPS_SUBMIT_BIO
        struct block_device_operations *ops = dattobd_get_bd_ops(dev->sd_base_dev->bdev);
#endif
        MAYBE_UNUSED(q);

#ifndef USE_BDOPS_SUBMIT_BIO
    if (GET_BIO_REQUEST_TRACKING_PTR(dev->sd_base_dev->bdev) != tracing_fn)
        return 0;
#endif

    //return 0 if there is another device tracing the same queue as dev.
    if (snap_devices) {
        tracer_for_each(cur_dev, i)
        {
            if (!cur_dev || test_bit(UNVERIFIED, &cur_dev->sd_state) || cur_dev == dev)
                continue;
#ifndef USE_BDOPS_SUBMIT_BIO
            if (q == bdev_get_queue(cur_dev->sd_base_dev->bdev))
                return 0;
#else
            if (ops == dattobd_get_bd_ops(cur_dev->sd_base_dev->bdev))
                return 0;
#endif
                }
        }
        return 1;
}

/**
 * __tracer_destroy_tracing() - 停止对 &struct snap_device 的跟踪，必要时恢复原始 MRF。
 *
 * @dev: &struct snap_device 对象指针。
 * @snap_devices: 快照设备数组。
 */
static void __tracer_destroy_tracing(struct snap_device *dev, snap_device_array_mut snap_devices)
{
    if (dev->sd_orig_request_fn) {
        LOG_DEBUG("replacing make_request_fn if needed");
        if (__tracer_should_reset_mrf(dev, snap_devices)) {
            LOG_DEBUG("__tracer_should_reset_mrf is true");

            if (!test_bit(ACTIVE, &dev->sd_state)) {
                int ret = 0;
                LOG_DEBUG("flushing bio requests");

                if (!test_bit(SNAPSHOT, &dev->sd_state)) {
                    ret = __tracer_setup_inc_cow_thread(dev, dev->sd_minor);
                } else {
                    ret = __tracer_setup_snap_cow_thread(dev, dev->sd_minor);
                }

                if (ret) {
                    LOG_ERROR(
                            ret,
                            "Failed to setup cow thread for device with minor %i and flush bio requests",
                            dev->sd_minor);
                }

                wake_up_process(dev->sd_cow_thread);
                //TODO: Maybe some waiting mechanism will be needed
                __tracer_destroy_cow_thread(dev);
            }

#ifndef USE_BDOPS_SUBMIT_BIO
            __tracer_transition_tracing(dev, dev->sd_base_dev->bdev, dev->sd_orig_request_fn,
                                        &snap_devices[dev->sd_minor], false);
#else
            __tracer_transition_tracing(dev, dev->sd_base_dev->bdev, dev->bd_ops,
                                        &snap_devices[dev->sd_minor], false);
#endif
        } else {
            __tracer_transition_tracing(dev, dev->sd_base_dev->bdev, NULL,
                                        &snap_devices[dev->sd_minor], false);
        }
        smp_wmb();
        dattobd_free_request_tracking_ptr(dev);

    } else if (snap_devices[dev->sd_minor] == dev) {
        smp_wmb();
        snap_devices[dev->sd_minor] = NULL;
        smp_wmb();
    }

    dev->sd_minor = 0;
    minor_range_recalculate(snap_devices);
}

/**
 * __tracer_setup_tracing_unverified() - 将 @dev 加入本驱动跟踪的快照设备数组。
 *
 * @dev: &struct snap_device 对象指针。
 * @minor: 设备次设备号。
 * @snap_devices: 快照设备数组。
 */
static void __tracer_setup_tracing_unverified(struct snap_device *dev, unsigned int minor,
                                              snap_device_array_mut snap_devices)
{
    minor_range_include(minor);
    smp_wmb();
    dev->sd_minor = minor;
    snap_devices[minor] = dev;
    smp_wmb();
}

/**
 * __tracer_setup_tracing() - 将 @minor 纳入跟踪范围，保存原 I/O 提交函数指针，
 *                            并用 tracing_fn 替换与本 &struct snap_device 关联的块设备的该指针。
 *
 * @dev: &struct snap_device 对象指针。
 * @minor: 设备次设备号。
 * @snap_devices: 快照设备数组。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __tracer_setup_tracing(struct snap_device *dev, unsigned int minor,
                                  snap_device_array_mut snap_devices)
{
    int ret = 0;

    dev->sd_minor = minor;
    minor_range_include(minor);

    // 获取基块设备的 make_request_fn
    LOG_DEBUG("getting the base block device's make_request_fn");

#ifndef USE_BDOPS_SUBMIT_BIO
    ret = dattobd_find_orig_mrf(dev->sd_base_dev->bdev, &dev->sd_orig_request_fn, snap_devices);
    if (ret)
        goto error;
    ret = __tracer_transition_tracing(dev, dev->sd_base_dev->bdev, tracing_fn, &snap_devices[minor],
                                      true);
#else
    if (!dev->sd_tracing_ops) {
        ret = find_orig_bdops(dev->sd_base_dev->bdev, &dev->bd_ops, &dev->sd_orig_request_fn,
                              &dev->sd_tracing_ops, snap_devices);
        if (ret)
            goto error;

        if (!dev->sd_tracing_ops) {
            LOG_DEBUG(
                    "allocating block_device_operations with submit_bio replaced by our tracing function");
            ret = tracer_alloc_ops(dev);
            if (ret) {
                goto error;
            }
        } else {
            LOG_DEBUG("using already existing tracing_ops");
        }

        ret = __tracer_transition_tracing(dev, dev->sd_base_dev->bdev, dev->sd_tracing_ops->bd_ops,
                                          &snap_devices[minor], true);
    } else {
        LOG_DEBUG("device with minor %i already has sd_tracing_ops", minor);
    }
#endif
    if (ret)
        goto error;
    return 0;

error:
    LOG_ERROR(ret, "error setting up tracing");
    dev->sd_minor = 0;
    dev->sd_orig_request_fn = NULL;
    minor_range_recalculate(snap_devices);
    return ret;
}

/**
 * __tracer_setup_unverified() - 为未验证设备建立跟踪。
 *
 * @dev: &struct snap_device 对象指针。
 * @minor: 设备次设备号。
 * @bdev_path: 块设备路径，如 '/dev/loop0'。
 * @cow_path: COW 后备文件路径。
 * @cache_size: COW 区段缓存大小上限（字节）。
 * @is_snap: 快照或增量（1 为快照，0 为增量）。
 * @snap_devices: 快照设备数组。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int __tracer_setup_unverified(struct snap_device *dev, unsigned int minor, const char *bdev_path,
                              const char *cow_path, unsigned long cache_size, int is_snap,
                              snap_device_array_mut snap_devices)
{
    LOG_DEBUG("Enter __tracer_setup_unverified path %s", bdev_path);

    if (is_snap)
        set_bit(SNAPSHOT, &dev->sd_state);
    else
        clear_bit(SNAPSHOT, &dev->sd_state);
    clear_bit(ACTIVE, &dev->sd_state);
    set_bit(UNVERIFIED, &dev->sd_state);

    dev->sd_cache_size = cache_size;

    dev->sd_bdev_path = kstrdup(bdev_path, GFP_KERNEL);
    if (!dev->sd_bdev_path)
        goto error;

    dev->sd_cow_path = kstrdup(cow_path, GFP_KERNEL);
    if (!dev->sd_cow_path)
        goto error;

    // 将 tracer 加入设备数组
    __tracer_setup_tracing_unverified(dev, minor, snap_devices);

    return 0;

error:
    LOG_ERROR(-ENOMEM, "error setting up unverified tracer");
    tracer_destroy(dev, snap_devices);
    return -ENOMEM;
}

/************************SETUP / DESTROY FUNCTIONS************************/

/**
 * tracer_destroy() - 拆除快照设备的跟踪并释放相关字段。
 *
 * @dev: &struct snap_device 对象指针。
 * @snap_devices: 快照设备数组。
 */
void tracer_destroy(struct snap_device *dev, snap_device_array_mut snap_devices)
{
    __tracer_destroy_tracing(dev, snap_devices);
    __tracer_destroy_cow_thread(dev);
    __tracer_destroy_snap(dev);
    __tracer_destroy_cow_path(dev);
    __tracer_destroy_cow_free(dev);
    __tracer_destroy_base_dev(dev);
}

/**
 * tracer_setup_active_snap() - 建立快照模式。
 *
 * @dev: &struct snap_device 对象指针。
 * @minor: 设备次设备号。
 * @bdev_path: 块设备路径，如 '/dev/loop0'。
 * @cow_path: COW 后备文件路径。
 * @fallocated_space: 0 表示使用默认预分配大小。
 * @cache_size: COW 区段缓存大小上限（字节）。
 * @snap_devices: 快照设备数组。
 *
 * 本调用会设置快照设备、创建含数据区的 COW 文件、确定 COW 路径、建立 COW 线程并启动跟踪。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int tracer_setup_active_snap(struct snap_device *dev, unsigned int minor, const char *bdev_path,
                             const char *cow_path, unsigned long fallocated_space,
                             unsigned long cache_size, snap_device_array_mut snap_devices)
{
    int ret;

    LOG_DEBUG("ENTER tracer_setup_active_snap");
    set_bit(SNAPSHOT, &dev->sd_state);
    set_bit(ACTIVE, &dev->sd_state);
    clear_bit(UNVERIFIED, &dev->sd_state);

    // 设置基设备
    ret = __tracer_setup_base_dev(dev, bdev_path, snap_devices);
    if (ret)
        goto error;

    // 设置 cow manager
    ret = __tracer_setup_cow_new(dev, dev->sd_base_dev->bdev, cow_path, dev->sd_size,
                                 fallocated_space, cache_size, NULL, 1);
    if (ret)
        goto error;

    // 设置 COW 路径
    ret = __tracer_setup_cow_path(dev, dev->sd_cow->dfilp);
    if (ret)
        goto error;

#ifndef USE_BDOPS_SUBMIT_BIO
    // 保留原 mrf 与块设备的关联
    ret = mrf_get(dev->sd_base_dev->bdev->bd_disk,
                  GET_BIO_REQUEST_TRACKING_PTR(dev->sd_base_dev->bdev));
    if (ret)
        goto error;
#endif

    // 设置快照相关字段
    ret = __tracer_setup_snap(dev, minor, dev->sd_base_dev->bdev, dev->sd_size);
    if (ret)
        goto error;

    // 创建并运行 COW 线程
    ret = __tracer_setup_snap_cow_thread(dev, minor);
    if (ret)
        goto error;

    wake_up_process(dev->sd_cow_thread);

    // 注入跟踪函数
    ret = __tracer_setup_tracing(dev, minor, snap_devices);
    if (ret)
        goto error;

    return 0;

error:
    LOG_ERROR(ret, "error setting up tracer as active snapshot");
    tracer_destroy(dev, snap_devices);
    return ret;
}

/************************NETLINK TRANSITION FUNCTIONS************************/

/**
 * tracer_active_snap_to_inc() - 从快照模式切换为增量跟踪。
 * @old_dev: 将被本调用替换的 &struct snap_device。
 * @snap_devices: 快照设备数组。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int tracer_active_snap_to_inc(struct snap_device *old_dev, snap_device_array_mut snap_devices)
{
    int ret;
    struct snap_device *dev;
    char *abs_path = NULL;
    int abs_path_len;

    // 分配新 tracer
    ret = tracer_alloc(&dev);
    if (ret)
        return ret;

    clear_bit(SNAPSHOT, &dev->sd_state);
    set_bit(ACTIVE, &dev->sd_state);
    clear_bit(UNVERIFIED, &dev->sd_state);

    // 拷贝/设置所需字段
    __tracer_copy_base_dev(old_dev, dev);
    __tracer_copy_cow_path(old_dev, dev);

    // 将 cow manager 拷贝到新设备；须确保不被多线程同时使用
    __tracer_copy_cow(old_dev, dev);

    // 设置 COW 线程
    ret = __tracer_setup_inc_cow_thread(dev, old_dev->sd_minor);
    if (ret)
        goto error;

    // 注入跟踪函数
    dev->sd_orig_request_fn = old_dev->sd_orig_request_fn;
    ret = __tracer_setup_tracing(dev, old_dev->sd_minor, snap_devices);
    if (ret)
        goto error;

    // 此后已绑定新设备，须确保其处于良好状态

    // 停止旧 COW 线程；须在启动新 COW 线程前完成以防并发访问
    __tracer_destroy_cow_thread(old_dev);

    // 关闭自动扩展
    cow_auto_expand_manager_free(old_dev->sd_cow->auto_expand);
    old_dev->sd_cow->auto_expand = NULL;

    // 确认清理旧 COW 线程时未发生错误
    ret = tracer_read_fail_state(old_dev);
    if (ret) {
        LOG_ERROR(ret, "errors occurred while cleaning up cow thread, putting "
                       "incremental into error state");
        tracer_set_fail_state(dev, ret);

        // 无论是否出错都要建好新线程以便清理已入队的 ssets
        wake_up_process(dev->sd_cow_thread);

        // 无论如何都清理旧设备
        __tracer_destroy_snap(old_dev);
        kfree(old_dev);

        return ret;
    }

    // 唤醒新 COW 线程；无论同步旧 COW 线程是否出错都要执行以免泄漏 I/O
    wake_up_process(dev->sd_cow_thread);

    // 截断 COW 文件
    ret = cow_truncate_to_index(dev->sd_cow);
    if (ret) {
        // 非致命错误，仅打警告
        file_get_absolute_pathname(dev->sd_cow->dfilp, &abs_path, &abs_path_len);
        if (!abs_path) {
            LOG_WARN(
                    "warning: cow file truncation failed, incremental will use more disk space than needed");
        } else {
            LOG_WARN(
                    "warning: failed to truncate '%s', incremental will use more disk space than needed",
                    abs_path);
            kfree(abs_path);
        }
    }

    // 销毁 old_dev 中不需要的字段及 old_dev 本身
    __tracer_destroy_snap(old_dev);
    kfree(old_dev);

    return 0;

error:
    LOG_ERROR(ret, "error transitioning to incremental mode");
    __tracer_destroy_cow_thread(dev);
    kfree(dev);

    return ret;
}

/**
 * tracer_active_inc_to_snap() - 从增量模式切换回快照模式。
 *
 * @old_dev: 当前以增量模式跟踪的 &struct snap_device。
 * @cow_path: COW 后备文件路径。
 * @fallocated_space: 0 表示沿用当前预分配设置。
 * @snap_devices: 快照设备数组。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 错误
 */
int tracer_active_inc_to_snap(struct snap_device *old_dev, const char *cow_path,
                              unsigned long fallocated_space, snap_device_array_mut snap_devices)
{
    int ret;
    struct snap_device *dev;

    LOG_DEBUG("ENTER tracer_active_inc_to_snap");

    // 分配新 tracer
    ret = tracer_alloc(&dev);
    if (ret)
        return ret;

    set_bit(SNAPSHOT, &dev->sd_state);
    set_bit(ACTIVE, &dev->sd_state);
    clear_bit(UNVERIFIED, &dev->sd_state);

    fallocated_space = (fallocated_space) ? fallocated_space : old_dev->sd_falloc_size;

    // 拷贝/设置所需字段
    __tracer_copy_base_dev(old_dev, dev);

    // 设置 cow manager
    ret = __tracer_setup_cow_new(dev, dev->sd_base_dev->bdev, cow_path, dev->sd_size,
                                 fallocated_space, dev->sd_cache_size, old_dev->sd_cow->uuid,
                                 old_dev->sd_cow->seqid + 1);
    if (ret)
        goto error;

    // 设置 COW 路径
    ret = __tracer_setup_cow_path(dev, dev->sd_cow->dfilp);
    if (ret)
        goto error;

    // 设置快照相关字段
    ret = __tracer_setup_snap(dev, old_dev->sd_minor, dev->sd_base_dev->bdev, dev->sd_size);
    if (ret)
        goto error;

    // 设置 COW 线程
    ret = __tracer_setup_snap_cow_thread(dev, old_dev->sd_minor);
    if (ret)
        goto error;

    // 开始跟踪（覆盖 old_dev 的跟踪）
    dev->sd_orig_request_fn = old_dev->sd_orig_request_fn;
    ret = __tracer_setup_tracing(dev, old_dev->sd_minor, snap_devices);
    if (ret)
        goto error;

    // 停止旧 COW 线程并启动新线程
    __tracer_destroy_cow_thread(old_dev);
    wake_up_process(dev->sd_cow_thread);

    // 销毁 old_dev 中不需要的字段及 old_dev 本身
    __tracer_destroy_cow_path(old_dev);
    __tracer_destroy_cow_sync_and_free(old_dev);
    kfree(old_dev);

    return 0;

error:
    LOG_ERROR(ret, "error transitioning tracer to snapshot mode");
    __tracer_destroy_cow_thread(dev);
    __tracer_destroy_snap(dev);
    __tracer_destroy_cow_path(dev);
    __tracer_destroy_cow_free(dev);
    kfree(dev);

    return ret;
}

/**
 * tracer_reconfigure() - 重新配置与 @dev 关联的缓存大小。
 *
 * @dev: &struct snap_device 对象指针。
 * @cache_size: COW 区段缓存大小上限（字节）。
 */
void tracer_reconfigure(struct snap_device *dev, unsigned long cache_size)
{
    dev->sd_cache_size = cache_size;
    if (!cache_size)
        cache_size = dattobd_cow_max_memory_default;
    if (test_bit(ACTIVE, &dev->sd_state))
        cow_modify_cache_size(dev->sd_cow, cache_size);
}

/**
 * tracer_dattobd_info() - 将 @dev 中当前相关信息拷贝到 @info。
 *
 * @dev: 跟踪块设备状态的源 &struct snap_device。
 * @info: 目标 &struct dattobd_info 对象指针。
 */
void tracer_dattobd_info(const struct snap_device *dev, struct dattobd_info *info)
{
    info->minor = dev->sd_minor;
    info->state = dev->sd_state;
    info->error = tracer_read_fail_state(dev);
    info->cache_size = (dev->sd_cache_size) ? dev->sd_cache_size : dattobd_cow_max_memory_default;
    strscpy(info->cow, dev->sd_cow_path, PATH_MAX);
    strscpy(info->bdev, dev->sd_bdev_path, PATH_MAX);

    if (!test_bit(UNVERIFIED, &dev->sd_state)) {
        info->falloc_size = dev->sd_cow->file_size;
        info->seqid = dev->sd_cow->seqid;
        memcpy(info->uuid, dev->sd_cow->uuid, COW_UUID_SIZE);
        info->version = dev->sd_cow->version;
        info->nr_changed_blocks = dev->sd_cow->nr_changed_blocks;
    } else {
        info->falloc_size = 0;
        info->seqid = 0;
        memset(info->uuid, 0, COW_UUID_SIZE);
    }
}

/************************AUTOMATIC TRANSITION FUNCTIONS************************/

/**
 * __tracer_active_to_dormant() - 从 ACTIVE 转为 DORMANT；例如底层块设备变为只读时调用。
 *
 * @dev: &struct snap_device 对象指针。
 */
void __tracer_active_to_dormant(struct snap_device *dev)
{
    int ret;

    LOG_DEBUG("ENTER __tracer_active_to_dormant");
    // 停止 COW 线程
    __tracer_destroy_cow_thread(dev);

    // 关闭 cow manager
    ret = __tracer_destroy_cow_sync_and_close(dev);
    if (ret)
        goto error;

    // 标记为休眠
    smp_wmb();
    clear_bit(ACTIVE, &dev->sd_state);

    return;

error:
    LOG_ERROR(ret, "error transitioning tracer to dormant state");
    tracer_set_fail_state(dev, ret);
}

/**
 * __tracer_unverified_snap_to_active() - 对原为未验证的设备启动跟踪并设为活动。
 *
 * @dev: &struct snap_device 对象指针。
 * @user_mount_path: 用户空间提供的路径，用于拼出 COW 文件路径。
 * @snap_devices: 快照设备数组。
 */
void __tracer_unverified_snap_to_active(struct snap_device *dev, const char __user *user_mount_path,
                                        snap_device_array_mut snap_devices)
{
    int ret;
    unsigned int minor = dev->sd_minor;
    char *cow_path, *bdev_path = dev->sd_bdev_path, *rel_path = dev->sd_cow_path;
    unsigned long cache_size = dev->sd_cache_size;

    LOG_DEBUG("ENTER __tracer_unverified_snap_to_active");
    // 设置结构体期间先移除跟踪
    __tracer_destroy_tracing(dev, snap_devices);

    // 标记为活动
    set_bit(ACTIVE, &dev->sd_state);
    clear_bit(UNVERIFIED, &dev->sd_state);

    dev->sd_bdev_path = NULL;
    dev->sd_cow_path = NULL;

    // 设置基设备
    ret = __tracer_setup_base_dev(dev, bdev_path, snap_devices);
    if (ret)
        goto error;

        // 生成完整路径
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
    ret = pathname_concat(user_mount_path, rel_path, &cow_path);
#else
    ret = user_mount_pathname_concat(user_mount_path, rel_path, &cow_path);
#endif
    if (ret)
        goto error;

    // 设置 cow manager
    ret = __tracer_setup_cow_reload_snap(dev, dev->sd_base_dev->bdev, cow_path, dev->sd_size,
                                         dev->sd_cache_size);
    if (ret)
        goto error;

    // 设置 COW 路径
    ret = __tracer_setup_cow_path(dev, dev->sd_cow->dfilp);
    if (ret)
        goto error;

#ifndef USE_BDOPS_SUBMIT_BIO
    // 保留原 mrf 与块设备的关联
    ret = mrf_get(dev->sd_base_dev->bdev->bd_disk,
                  GET_BIO_REQUEST_TRACKING_PTR(dev->sd_base_dev->bdev));
    if (ret)
        goto error;
#endif

    // 设置快照相关字段
    ret = __tracer_setup_snap(dev, minor, dev->sd_base_dev->bdev, dev->sd_size);
    if (ret)
        goto error;

    // 创建并运行 COW 线程
    ret = __tracer_setup_snap_cow_thread(dev, minor);
    if (ret)
        goto error;

    wake_up_process(dev->sd_cow_thread);

    // 注入跟踪函数
    ret = __tracer_setup_tracing(dev, minor, snap_devices);
    if (ret)
        goto error;

    kfree(bdev_path);
    kfree(rel_path);
    kfree(cow_path);

    return;

error:
    LOG_ERROR(ret, "error transitioning snapshot tracer to active state");
    tracer_destroy(dev, snap_devices);
    tracer_setup_unverified_snap(dev, minor, bdev_path, rel_path, cache_size, snap_devices);
    tracer_set_fail_state(dev, ret);
    kfree(bdev_path);
    kfree(rel_path);
    if (cow_path)
        kfree(cow_path);
}

/**
 * __tracer_unverified_inc_to_active() - 从未验证状态转为活动状态。
 * @dev: &struct snap_device 对象指针。
 * @user_mount_path: 用户空间提供的路径，用于拼出 COW 文件路径。
 * @snap_devices: 快照设备数组。
 *
 * 本调用完成后即完成对块设备的跟踪配置。
 */
void __tracer_unverified_inc_to_active(struct snap_device *dev, const char __user *user_mount_path,
                                       snap_device_array_mut snap_devices)
{
    int ret;
    unsigned int minor = dev->sd_minor;
    char *cow_path, *bdev_path = dev->sd_bdev_path, *rel_path = dev->sd_cow_path;
    unsigned long cache_size = dev->sd_cache_size;

    LOG_DEBUG("ENTER %s", __func__);

    // 设置结构体期间先移除跟踪
    __tracer_destroy_tracing(dev, snap_devices);

    // 标记为活动
    set_bit(ACTIVE, &dev->sd_state);
    clear_bit(UNVERIFIED, &dev->sd_state);

    dev->sd_bdev_path = NULL;
    dev->sd_cow_path = NULL;

    // 设置基设备
    ret = __tracer_setup_base_dev(dev, bdev_path, snap_devices);
    if (ret)
        goto error;

        // 生成完整路径
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
    ret = pathname_concat(user_mount_path, rel_path, &cow_path);
#else
    ret = user_mount_pathname_concat(user_mount_path, rel_path, &cow_path);
#endif
    if (ret)
        goto error;

    // 设置 cow manager
    ret = __tracer_setup_cow_reload_inc(dev, dev->sd_base_dev->bdev, cow_path, dev->sd_size,
                                        dev->sd_cache_size);
    if (ret)
        goto error;

    // 设置 COW 路径
    ret = __tracer_setup_cow_path(dev, dev->sd_cow->dfilp);
    if (ret)
        goto error;

#ifndef USE_BDOPS_SUBMIT_BIO
    // 保留原 mrf 与块设备的关联
    ret = mrf_get(dev->sd_base_dev->bdev->bd_disk,
                  GET_BIO_REQUEST_TRACKING_PTR(dev->sd_base_dev->bdev));
    if (ret)
        goto error;
#endif

    // 创建并运行 COW 线程
    ret = __tracer_setup_inc_cow_thread(dev, minor);
    if (ret)
        goto error;

    wake_up_process(dev->sd_cow_thread);

    // 注入跟踪函数
    ret = __tracer_setup_tracing(dev, minor, snap_devices);
    if (ret)
        goto error;

    kfree(bdev_path);
    kfree(rel_path);
    kfree(cow_path);

    return;

error:
    LOG_ERROR(ret, "error transitioning incremental to active state");
    tracer_destroy(dev, snap_devices);
    tracer_setup_unverified_inc(dev, minor, bdev_path, rel_path, cache_size, snap_devices);
    tracer_set_fail_state(dev, ret);
    kfree(bdev_path);
    kfree(rel_path);
    if (cow_path)
        kfree(cow_path);
}

/**
 * __tracer_dormant_to_active() - 在曾跟踪过的设备上重新启动跟踪。
 * @dev: &struct snap_device 对象指针。
 * @user_mount_path: 用户空间提供的路径，用于拼出 COW 文件路径。
 *
 * 按先前模式（快照或增量）继续跟踪。
 */
void __tracer_dormant_to_active(struct snap_device *dev, const char __user *user_mount_path)
{
    int ret;
    char *cow_path;

    LOG_DEBUG("ENTER __tracer_dormant_to_active");

    // 生成完整路径

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
    ret = pathname_concat(user_mount_path, dev->sd_cow_path, &cow_path);
#else
    ret = user_mount_pathname_concat(user_mount_path, dev->sd_cow_path, &cow_path);
#endif
    if (ret)
        goto error;

    // 设置 cow manager
    ret = __tracer_setup_cow_reopen(dev, dev->sd_base_dev->bdev, cow_path);
    if (ret)
        goto error;

    // 重启 COW 线程
    if (test_bit(SNAPSHOT, &dev->sd_state))
        ret = __tracer_setup_snap_cow_thread(dev, dev->sd_minor);
    else
        ret = __tracer_setup_inc_cow_thread(dev, dev->sd_minor);

    if (ret)
        goto error;

    wake_up_process(dev->sd_cow_thread);

    // 将状态设为活动
    smp_wmb();
    set_bit(ACTIVE, &dev->sd_state);
    clear_bit(UNVERIFIED, &dev->sd_state);

    kfree(cow_path);

    return;

error:
    LOG_ERROR(ret, "error transitioning tracer to active state");
    if (cow_path)
        kfree(cow_path);
    tracer_set_fail_state(dev, ret);
}

int tracer_expand_cow_file_no_check(struct snap_device *dev, uint64_t by_size_bytes)
{
    int ret;
    LOG_DEBUG("ENTER tracer_expand_cow_file_no_check");
    if (tracer_read_fail_state(dev)) {
        LOG_ERROR(-EBUSY, "cannot expand cow file for device in error state");
        return -EBUSY;
    }

    ret = __cow_expand_datastore(dev->sd_cow, by_size_bytes);

    if (ret) {
        LOG_ERROR(ret, "error expanding cow file");
        tracer_set_fail_state(dev, ret);
        // __tracer_destroy_cow_thread(dev); -- we can't ask for thread destroy, as this function may be called from cow thread
        // cow_thread 很快会失败
    }

    return ret;
}
