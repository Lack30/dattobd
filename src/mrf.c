// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "mrf.h"
#include "includes.h"
#include "snap_device.h"
#include "hints.h"

#ifdef HAVE_BLK_ALLOC_QUEUE
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/blk-mq.h>
#include <linux/percpu-refcount.h>
#endif

#ifdef HAVE_MAKE_REQUEST_FN_INT
int dattobd_call_mrf(make_request_fn *fn, struct request_queue *q, struct bio *bio)
{
    return fn(q, bio);
}
#elif defined HAVE_MAKE_REQUEST_FN_VOID
int dattobd_call_mrf(make_request_fn *fn, struct request_queue *q, struct bio *bio)
{
    fn(q, bio);
    return 0;
}
#elif !defined USE_BDOPS_SUBMIT_BIO
int dattobd_call_mrf(make_request_fn *fn, struct request_queue *q, struct bio *bio)
{
    return fn(q, bio);
}
#endif

#ifdef HAVE_BLK_ALLOC_QUEUE
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
MRF_RETURN_TYPE dattobd_null_mrf(struct request_queue *q, struct bio *bio)
{
    percpu_ref_get(&q->q_usage_counter);
    // 为给定 request_queue 走 blk_mq 的 make_request 路径
    return blk_mq_make_request(q, bio);
}
#endif

#ifdef USE_BDOPS_SUBMIT_BIO

MRF_RETURN_TYPE(*dattobd_blk_mq_submit_bio)
(struct bio *) = (BLK_MQ_SUBMIT_BIO_ADDR != 0) ?
                         (MRF_RETURN_TYPE(*)(struct bio *))(BLK_MQ_SUBMIT_BIO_ADDR +
                                                            (long long)(((void *)kfree) -
                                                                        (void *)KFREE_ADDR)) :
                         NULL;

MRF_RETURN_TYPE dattobd_snap_null_mrf(struct bio *bio)
{
#ifdef HAVE_NONVOID_SUBMIT_BIO_1
    MRF_RETURN_TYPE exists_to_align_api_only = BLK_QC_T_NONE;
#endif

#ifdef HAVE_BLK_ALLOC_QUEUE
    percpu_ref_get(&(dattobd_bio_bi_disk(bio))->queue->q_usage_counter);
#endif
    dattobd_blk_mq_submit_bio(bio);
#ifdef HAVE_NONVOID_SUBMIT_BIO_1
    return exists_to_align_api_only;
#else
    return;
#endif
}

MRF_RETURN_TYPE dattobd_null_mrf(struct bio *bio)
{
    // 在把 bio 提交到原设备前：若 bio_list 中存在非本 bio 的项，则将其重新入队并提前返回，
    // 因为提交时也会如此。submit_bio 会限制同时仅有一个 bio 活跃；tracing_fn 本身即由
    // submit_bio 调用，故须在仅当列表中唯一项为本 bio 时清空 bio_list。
    if (current->bio_list) {
        struct bio *bio_in_list = current->bio_list->head;
        while (bio_in_list) {
            if (bio_in_list != bio) {
                bio_list_add(&current->bio_list[0], bio);
                MRF_RETURN(0); // 返回 BLK_QC_T_NONE
            }
            bio_in_list = bio_in_list->bi_next;
        }
        current->bio_list = NULL; // 勿 free，其在栈上分配
    }
    // 此处使用全局 submit_bio，而非 block_device_operations 的 submit_bio 成员，
    // 以便向真实磁盘提交 I/O；内核内部 submit_bio 实现也会处理空函数指针。
    return submit_bio(bio);
}

int dattobd_call_mrf_real(struct snap_device *dev, struct bio *bio)
{
    return dattobd_call_mrf(dev->sd_orig_request_fn, dattobd_bio_get_queue(bio), bio);
}

int dattobd_call_mrf(make_request_fn *fn, struct request_queue *q, struct bio *bio)
{
    fn(bio);
    return 0;
}

make_request_fn *dattobd_get_gd_mrf(struct gendisk *gd)
{
    return gd->fops->submit_bio;
}

struct block_device_operations *dattobd_get_bd_ops(struct block_device *bdev)
{
    return (struct block_device_operations *)bdev->bd_disk->fops;
}

#else
int dattobd_call_mrf_real(struct snap_device *dev, struct bio *bio)
{
    return dattobd_call_mrf(dev->sd_orig_request_fn, dattobd_bio_get_queue(bio), bio);
}

make_request_fn *dattobd_get_gd_mrf(struct gendisk *gd)
{
    return gd->queue->make_request_fn;
}
#endif

make_request_fn *dattobd_get_bd_mrf(struct block_device *bdev)
{
    return dattobd_get_gd_mrf(bdev->bd_disk);
}
