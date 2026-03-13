// SPDX-License-Identifier: GPL-2.0-only

/*
 * 与 bio_queue 结构操作相关的代码。
 *
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 实现带自旋锁与等待队列的 bio FIFO 队列，并提供读请求延后以避让重叠写请求的出队逻辑。
 */

#include "bio_queue.h"
#include "bio_helper.h"

/**
 * bio_queue_init() - 初始化队列以供使用。
 * @bq: 队列。
 */
void bio_queue_init(struct bio_queue *bq)
{
    bio_list_init(&bq->bios);
    spin_lock_init(&bq->lock);
    init_waitqueue_head(&bq->event);
}

/**
 * bio_queue_empty() - 检查队列是否为空。
 * @bq: 队列。
 *
 * Return: 0 表示非空，非 0 表示空。
 */
int bio_queue_empty(const struct bio_queue *bq)
{
    return bio_list_empty(&bq->bios);
}

/**
 * bio_queue_add() - 将元素加入队列末尾。
 * @bq: 队列。
 * @bio: 要加入队列的元素。
 */
void bio_queue_add(struct bio_queue *bq, struct bio *bio)
{
    unsigned long flags;

    spin_lock_irqsave(&bq->lock, flags);
    bio_list_add(&bq->bios, bio);
    spin_unlock_irqrestore(&bq->lock, flags);
    wake_up(&bq->event);
}

/**
 * bio_queue_dequeue() - 从队列头部取出一个元素。
 * @bq: 队列。
 *
 * 从 @bq 中按先进先出顺序移除并返回一个元素。
 *
 * Return: 被移除的元素。
 */
struct bio *bio_queue_dequeue(struct bio_queue *bq)
{
    unsigned long flags;
    struct bio *bio;

    spin_lock_irqsave(&bq->lock, flags);
    bio = bio_list_pop(&bq->bios);
    spin_unlock_irqrestore(&bq->lock, flags);

    return bio;
}

/**
 * bio_overlap() - 检查两次块 I/O 操作是否重叠。
 * @bio1: 第一次块 I/O 操作。
 * @bio2: 第二次块 I/O 操作。
 *
 * Return: 0 表示不重叠，非 0 表示重叠。
 */
static int bio_overlap(const struct bio *bio1, const struct bio *bio2)
{
    return max(bio_sector(bio1), bio_sector(bio2)) <=
           min(bio_sector(bio1) + (bio_size(bio1) / SECTOR_SIZE),
               bio_sector(bio2) + (bio_size(bio2) / SECTOR_SIZE));
}

/**
 * bio_queue_dequeue_delay_read() - 取出下一个待处理的 &struct bio；若队首为读操作且存在
 *                                  尚未处理的重叠写操作，则先返回该写操作，将读操作重新插入队尾延后处理。
 *
 * @bq: &struct bio_queue 对象指针。
 *
 * Context: 调用时队列 @bq 必须非空。
 *
 * Return: 本次取出的块 I/O 操作。
 */
struct bio *bio_queue_dequeue_delay_read(struct bio_queue *bq)
{
    unsigned long flags;
    struct bio *bio, *tmp, *prev = NULL;

    spin_lock_irqsave(&bq->lock, flags);

    bio = bio_list_pop(&bq->bios);

    if (!bio_data_dir(bio)) {
        bio_list_for_each (tmp, &bq->bios) {
            if (bio_data_dir(tmp) && bio_overlap(bio, tmp)) {
                if (prev)
                    prev->bi_next = bio;
                else
                    bq->bios.head = bio;

                if (bq->bios.tail == tmp)
                    bq->bios.tail = bio;

                bio->bi_next = tmp->bi_next;
                tmp->bi_next = NULL;
                bio = tmp;

                goto out;
            }
            prev = tmp;
        }
    }

out:
    spin_unlock_irqrestore(&bq->lock, flags);

    return bio;
}
