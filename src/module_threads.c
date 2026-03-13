// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "module_threads.h"
#include "bio_helper.h"
#include "bio_queue.h"
#include "cow_manager.h"
#include "logging.h"
#include "mrf.h"
#include "snap_device.h"
#include "snap_handle.h"
#include "sset_queue.h"
#include "submit_bio.h"
#include "tracer_helper.h"

/* MIN_NICE 在 3.16 及以上内核中定义 */
#ifndef MIN_NICE
#define MIN_NICE -20
#endif

/**
 * inc_sset_thread() - 线程入口：从队列取出 sector set 并交给处理逻辑。
 * @data: &struct snap_device 对象指针。
 *
 * 若发生错误则清空队列，剩余 sset 直接释放不再处理。
 *
 * Return: 恒为 0。
 */
int inc_sset_thread(void *data)
{
    int ret, is_failed = 0;
    struct snap_device *dev = data;
    struct sset_queue *sq = &dev->sd_pending_ssets;
    struct sector_set *sset;

    // 将本线程设为允许的最高优先级
    set_user_nice(current, MIN_NICE);

    while (!kthread_should_stop() || !sset_queue_empty(sq)) {
        // 等待待处理 sset 或 kthread_stop 调用
        wait_event_interruptible(sq->event, kthread_should_stop() || !sset_queue_empty(sq));

        if (!is_failed && tracer_read_fail_state(dev)) {
            LOG_DEBUG("error detected in sset thread, cleaning up cow");
            is_failed = 1;

            if (dev->sd_cow)
                cow_free_members(dev->sd_cow);
        }

        if (sset_queue_empty(sq))
            continue;

        // 安全出队一个 sset
        sset = sset_queue_dequeue(sq);

        // 若已出错则不再处理，仅释放已有项
        if (is_failed) {
            kfree(sset);
            continue;
        }

        // 将 sset 交给处理函数
        ret = inc_handle_sset(dev, sset);
        if (ret) {
            LOG_ERROR(ret, "error handling sector set in kernel thread");
            tracer_set_fail_state(dev, ret);
        }

        // 释放 sector set
        kfree(sset);
    }

    return 0;
}

/**
 * snap_cow_thread() - 依次将 BIO 交给相应的读/写处理函数处理。
 *
 * @data: &struct snap_device 对象指针。
 *
 * Return: 恒为 0。
 */
int snap_cow_thread(void *data)
{
    int ret, is_failed = 0;
    struct snap_device *dev = data;
    struct bio_queue *bq = &dev->sd_cow_bios;
    struct bio *bio;

    // 将本线程设为允许的最高优先级
    set_user_nice(current, MIN_NICE);

    while (!kthread_should_stop() || !bio_queue_empty(bq) ||
           atomic64_read(&dev->sd_submitted_cnt) != atomic64_read(&dev->sd_received_cnt)) {
        // 等待待处理 bio 或 kthread_stop 调用
        wait_event_interruptible(bq->event, kthread_should_stop() || !bio_queue_empty(bq));

        if (!is_failed && tracer_read_fail_state(dev)) {
            LOG_DEBUG("error detected in cow thread, cleaning up cow");
            is_failed = 1;

            if (dev->sd_cow)
                cow_free_members(dev->sd_cow);
        }

        if (bio_queue_empty(bq))
            continue;

        // 安全出队一个 bio
        bio = bio_queue_dequeue_delay_read(bq);

        // 将 bio 交给处理函数
        if (!bio_data_dir(bio)) {
            // 若处于失败状态则返回 I/O 错误并释放 bio
            if (is_failed) {
                dattobd_bio_endio(bio, -EIO);
                continue;
            }

            ret = snap_handle_read_bio(dev, bio);
            if (ret) {
                LOG_ERROR(ret, "error handling read bio in kernel thread");
                tracer_set_fail_state(dev, ret);
            }

            dattobd_bio_endio(bio, (ret) ? -EIO : 0);
        } else {
            if (is_failed) {
                bio_free_clone(bio);
                continue;
            }

            ret = snap_handle_write_bio(dev, bio);
            if (ret) {
                LOG_ERROR(ret, "error handling write bio in kernel thread");
                tracer_set_fail_state(dev, ret);
            }

            bio_free_clone(bio);
        }
    }

    return 0;
}

/**
 * snap_mrf_thread() - 将原始 BIO 逐个提交到块 I/O 层。
 *
 * @data: &struct snap_device 对象指针。
 *
 * Return: 恒为 0。
 */
int snap_mrf_thread(void *data)
{
    int ret = 0;
    struct snap_device *dev = data;
    struct bio_queue *bq = &dev->sd_orig_bios;
    struct bio *bio = NULL;

    MAYBE_UNUSED(ret);

    // 将本线程设为允许的最高优先级
    set_user_nice(current, MIN_NICE);

    while (!kthread_should_stop() || !bio_queue_empty(bq)) {
        // 等待待处理 bio 或 kthread_stop 调用
        wait_event_interruptible(bq->event, kthread_should_stop() || !bio_queue_empty(bq));
        if (bio_queue_empty(bq))
            continue;

        // 安全出队一个 bio
        bio = bio_queue_dequeue(bq);

        // 将原始 bio 提交到块 I/O 层
        dattobd_bio_op_set_flag(bio, DATTOBD_PASSTHROUGH);

        SUBMIT_BIO_REAL(dev, bio);
#ifdef HAVE_MAKE_REQUEST_FN_INT
        if (ret)
            generic_make_request(bio);
#endif
    }

    return 0;
}
