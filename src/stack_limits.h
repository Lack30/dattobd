// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2025 Datto Inc.
 */

#ifndef STACK_LIMITS_H_
#define STACK_LIMITS_H_

#include "logging.h"

// dattobd_bdev_stack_limits(request_queue, bdev, sector_t) — 本模块封装

// queue_limits_stack_bdev — 自 6.9 起
// bdev_stack_limits — 自 2.6.33 至 5.8
// blk_stack_limits — 自 2.6.31 起

// dattobd_blk_set_stacking_limits — 本模块封装

// blk_set_stacking_limits — 自 3.3 起
// blk_set_default_limits — 自 2.6.31 至 6.1


#if defined(HAVE_QUEUE_LIMITS_STACK_BDEV)

// 若可用则优先使用 queue_limits_stack_bdev

#define dattobd_bdev_stack_limits(rq, bd, sec) queue_limits_stack_bdev(&(rq)->limits, bd, sec, DATTO_TAG)

#else

// 若无 queue_limits_stack_bdev 则用 bdev_stack_limits，再无可用时自行模拟

#if !defined(HAVE_BDEV_STACK_LIMITS)

static int bdev_stack_limits(struct queue_limits *t, struct block_device *bdev, sector_t start){
    struct request_queue *bq = bdev_get_queue(bdev);
    start += get_start_sect(bdev);
    return blk_stack_limits(t, &bq->limits, start << 9);
}

#endif

#define dattobd_bdev_stack_limits(rq, bd, sec) bdev_stack_limits(&(rq)->limits, bd, sec)

#endif

#if !defined(HAVE_BLK_SET_STACKING_LIMITS)

#define blk_set_stacking_limits(lim) blk_set_default_limits(lim)

#endif

#endif