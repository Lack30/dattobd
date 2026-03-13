// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 定义快照设备的核心数据结构、状态位以及全局设备数组访问接口。
 */

#ifndef SNAP_DEVICE_H_
#define SNAP_DEVICE_H_

#include "bio_helper.h" // needed for USE_BDOPS_SUBMIT_BIO to be defined
#include "bio_queue.h"
#include "bio_request_callback.h"
#include "includes.h"
#include "submit_bio.h"
#include "sset_queue.h"
#include "blkdev.h"

// 跟踪结构体状态位偏移宏
#define SNAPSHOT 0
#define ACTIVE 1
#define UNVERIFIED 2

#ifdef USE_BDOPS_SUBMIT_BIO
struct tracing_ops {
    struct block_device_operations *bd_ops;
    atomic_t refs;
#ifdef HAVE_BD_HAS_SUBMIT_BIO
    bool has_submit_bio;
#endif
};

static inline struct tracing_ops *tracing_ops_get(struct tracing_ops *trops)
{
    if (trops)
        atomic_inc(&trops->refs);
    return trops;
}

static inline void tracing_ops_put(struct tracing_ops *trops)
{
    // 释放对 tracing_ops 的引用
    if (atomic_dec_and_test(&trops->refs)) {
        kfree(trops->bd_ops);
        kfree(trops);
    }
}
#endif

struct block_change_stream;

struct snap_device {
    unsigned int sd_minor; // 快照设备次设备号
    unsigned long sd_state; // 快照当前状态
    unsigned long sd_falloc_size; // COW 文件预分配空间（兆字节）
    unsigned long sd_cache_size; // 最大缓存大小（字节）
    atomic_t sd_refs; // 已打开该设备的用户数
    atomic_t sd_fail_code; // 失败返回码
    atomic_t sd_active; // 快照设备是否已就绪并跟踪 I/O
    sector_t sd_sect_off; // 基块设备起始扇区
    sector_t sd_size; // 设备大小（扇区数）
    struct request_queue *sd_queue; // 快照设备请求队列
    struct gendisk *sd_gd; // 快照设备 gendisk
    struct bdev_wrapper *sd_base_dev; // 被快照的基设备
    char *sd_bdev_path; // 基设备文件路径
    struct cow_manager *sd_cow; // cow manager
    char *sd_cow_path; // COW 文件路径
    struct inode *sd_cow_inode; // COW 文件 inode
    BIO_REQUEST_CALLBACK_FN *sd_orig_request_fn; // 块设备原 make_request_fn 或 submit_bio 函数指针
    struct task_struct *sd_cow_thread; // 处理 COW 读写的线程
    struct bio_queue sd_cow_bios; // 未完成 COW bio 队列
    struct task_struct *sd_mrf_thread; // 处理读写的 MRF 线程
    struct bio_queue sd_orig_bios; // 未完成原始 bio 队列
    struct sset_queue sd_pending_ssets; // 待处理 sector set 队列
    struct block_change_stream *sd_bcs; // block change stream 运行时状态
    struct fiemap_extent *sd_cow_extents; // COW 文件区段
    unsigned int sd_cow_ext_cnt; // COW 文件区段数量
#ifndef HAVE_BIOSET_INIT
    //#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
    struct bio_set *sd_bioset; // bio 分配池
#else
    struct bio_set sd_bioset; // bio 分配池
#endif
    atomic64_t sd_submitted_cnt; // 已提交到底层驱动的读克隆数
    atomic64_t sd_received_cnt; // 已提交的读克隆数
#ifdef USE_BDOPS_SUBMIT_BIO
    struct block_device_operations *bd_ops;
    struct tracing_ops *sd_tracing_ops; // 原 block_device_operations 的拷贝，含用于跟踪的请求函数
#endif
};

int init_snap_device_array(void);
void cleanup_snap_device_array(void);

typedef struct snap_device *const *snap_device_array;
typedef struct snap_device **snap_device_array_mut;

snap_device_array get_snap_device_array(void);
snap_device_array_mut get_snap_device_array_mut(void);
snap_device_array get_snap_device_array_nolock(void);
void put_snap_device_array(snap_device_array);
void put_snap_device_array_mut(snap_device_array_mut);
void put_snap_device_array_nolock(snap_device_array);

#endif /* SNAP_DEVICE_H_ */
