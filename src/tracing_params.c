// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "tracing_params.h"
#include "bio_helper.h"
#include "bio_queue.h"
#include "includes.h"
#include "logging.h"
#include "snap_device.h"

/**
 * tp_alloc() - 分配并初始化跟踪参数，并增加引用计数。
 *
 * @dev: &struct snap_device 对象指针。
 * @bio: 描述此次 I/O 的 &struct bio。
 * @tp_out: 调用方持有的 &struct tracing_params，需用 kfree() 释放。
 *
 * Return: 0 表示成功，非 0 为表示错误的 errno。
 */
int tp_alloc(struct snap_device *dev, struct bio *bio, struct tracing_params **tp_out)
{
    struct tracing_params *tp;

    tp = kzalloc(1 * sizeof(struct tracing_params), GFP_NOIO);
    if (!tp) {
        LOG_ERROR(-ENOMEM, "error allocating tracing parameters struct");
        *tp_out = tp;
        return -ENOMEM;
    }

    tp->dev = dev;
    tp->orig_bio = bio;
    tp->bio_sects.head = NULL;
    tp->bio_sects.tail = NULL;
    atomic_set(&tp->refs, 1);

    *tp_out = tp;
    return 0;
}

/**
 * tp_get() - 增加引用计数。
 *
 * @tp: &struct tracing_params 对象指针。
 */
void tp_get(struct tracing_params *tp)
{
    atomic_inc(&tp->refs);
}

/**
 * tp_put() - 减少引用计数；若变为 0 则释放与 @tp 关联的内存。
 *
 * @tp: &struct tracing_params 对象指针。
 */
void tp_put(struct tracing_params *tp)
{
    // 减少对 tp 的引用
    if (atomic_dec_and_test(&tp->refs)) {
        struct bio_sector_map *next, *curr = NULL;

        // 无引用后即可释放 orig_bio
        bio_queue_add(&tp->dev->sd_orig_bios, tp->orig_bio);

        // 释放 sector map 链表中的节点
        for (curr = tp->bio_sects.head; curr != NULL; curr = next) {
            next = curr->next;
            kfree(curr);
        }
        kfree(tp);
    }
}

/**
 * tp_add() - 将 @bio 加入 &struct tracing_params。
 *
 * @tp: &struct tracing_params 对象指针。
 * @bio: 描述此次 I/O 的 &struct bio。
 *
 * Return: 0 表示成功，非 0 为表示错误的 errno。
 */
int tp_add(struct tracing_params *tp, struct bio *bio)
{
    struct bio_sector_map *map;
    map = kzalloc(1 * sizeof(struct bio_sector_map), GFP_NOIO);
    if (!map) {
        LOG_ERROR(-ENOMEM, "error allocating new bio_sector_map struct");
        return -ENOMEM;
    }

    map->bio = bio;
    map->sect = bio_sector(bio);
    map->size = bio_size(bio);
    map->next = NULL;
    if (tp->bio_sects.head == NULL) {
        tp->bio_sects.head = map;
        tp->bio_sects.tail = map;
    } else {
        tp->bio_sects.tail->next = map;
        tp->bio_sects.tail = map;
    }
    return 0;
}
