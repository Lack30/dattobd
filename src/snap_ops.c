// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "snap_ops.h"

#include "includes.h"
#include "logging.h"
#include "snap_device.h"
#include "tracer_helper.h"

/**
 * __tracer_add_ref() - 增加 &snap_device->sd_refs 的引用计数。
 *
 * @dev: &struct snap_device 对象指针。
 * @ref_cnt: 要增加的引用数（可为负表示减少）。
 *
 * Return:
 * 0 - 成功
 * !0 - 表示错误的 errno
 */
static int __tracer_add_ref(struct snap_device *dev, int ref_cnt)
{
    int ret = 0;

    if (!dev) {
        ret = -EFAULT;
        LOG_ERROR(ret, "requested snapshot device does not exist");
        goto error;
    }

    atomic_add(ref_cnt, &dev->sd_refs);

error:
    return ret;
}

#define __tracer_open(dev) __tracer_add_ref(dev, 1)
#define __tracer_close(dev) __tracer_add_ref(dev, -1)

#ifdef HAVE_BDOPS_OPEN_INODE
//#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

static int snap_open(struct inode *inode, struct file *filp)
{
    return __tracer_open(inode->i_bdev->bd_disk->private_data);
}

static int snap_release(struct inode *inode, struct file *filp)
{
    return __tracer_close(inode->i_bdev->bd_disk->private_data);
}
#elif defined HAVE_BDOPS_OPEN_INT
//#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)

static int snap_open(struct block_device *bdev, fmode_t mode)
{
    return __tracer_open(bdev->bd_disk->private_data);
}

static int snap_release(struct gendisk *gd, fmode_t mode)
{
    return __tracer_close(gd->private_data);
}
#elif defined HAVE_BDOPS_OPEN_WITH_BLK_MODE
static int snap_open(struct gendisk *gd, blk_mode_t mode)
{
    (void)mode;
    return __tracer_open(gd->private_data);
}

static void snap_release(struct gendisk *gd)
{
    __tracer_close(gd->private_data);
}
#else
static int snap_open(struct block_device *bdev, fmode_t mode)
{
    return __tracer_open(bdev->bd_disk->private_data);
}

static void snap_release(struct gendisk *gd, fmode_t mode)
{
    __tracer_close(gd->private_data);
}
#endif

#ifndef USE_BDOPS_SUBMIT_BIO
/* 内核版本 < 5.9 */
MRF_RETURN_TYPE snap_mrf(struct request_queue *q, struct bio *bio)
{
    struct snap_device *dev = q->queuedata;
#else
/* 内核版本 >= 5.9 */
MRF_RETURN_TYPE snap_mrf(struct bio *bio)
{
    struct snap_device *dev = dattobd_bio_bi_disk(bio)->queue->queuedata;
#endif
    // 若有写请求误入则丢弃
    if (bio_data_dir(bio)) {
        dattobd_bio_endio(bio, -EOPNOTSUPP);
        MRF_RETURN(0);
    } else if (tracer_read_fail_state(dev)) {
        dattobd_bio_endio(bio, -EIO);
        MRF_RETURN(0);
    } else if (!test_bit(ACTIVE, &dev->sd_state)) {
        dattobd_bio_endio(bio, -EBUSY);
        MRF_RETURN(0);
    }

    // 将 bio 入队由内核线程处理
    bio_queue_add(&dev->sd_cow_bios, bio);

    MRF_RETURN(0);
}

static const struct block_device_operations snap_ops = { .owner = THIS_MODULE,
                                                         .open = snap_open,
                                                         .release = snap_release,
#ifdef USE_BDOPS_SUBMIT_BIO
                                                         .submit_bio = snap_mrf
#endif
};

const struct block_device_operations *get_snap_ops(void)
{
    return &snap_ops;
}
