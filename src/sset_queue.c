// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "sset_queue.h"
#include "sset_list.h"

/**
 * sset_queue_init() - 初始化 &struct sset_queue 以供使用。
 * @sq: &struct sset_queue 对象指针。
 */
void sset_queue_init(struct sset_queue *sq)
{
    sset_list_init(&sq->ssets);
    spin_lock_init(&sq->lock);
    init_waitqueue_head(&sq->event);
}

/**
 * sset_queue_empty() - 检查 &struct sset_queue 是否为空。
 *
 * @sq: &struct sset_queue 对象指针。
 *
 * Return: 空时为 0，否则非 0。
 */
int sset_queue_empty(const struct sset_queue *sq)
{
    return sset_list_empty(&sq->ssets);
}

/**
 * sset_queue_add() - 将 @sset 加入队列 @sq。
 *
 * @sq: &struct sset_queue 对象指针。
 * @sset: 要加入 @sq 的 &struct sector_set 对象指针。
 */
void sset_queue_add(struct sset_queue *sq, struct sector_set *sset)
{
    unsigned long flags;

    spin_lock_irqsave(&sq->lock, flags);
    sset_list_add(&sq->ssets, sset);
    spin_unlock_irqrestore(&sq->lock, flags);
    wake_up(&sq->event);
}

/**
 * sset_queue_dequeue() - 从 @sq 队首取出一个元素。
 *
 * @sq: &struct sset_queue 对象指针。
 *
 * Return: 队首元素，空队列返回 NULL。
 */
struct sector_set *sset_queue_dequeue(struct sset_queue *sq)
{
    unsigned long flags;
    struct sector_set *sset;

    spin_lock_irqsave(&sq->lock, flags);
    sset = sset_list_pop(&sq->ssets);
    spin_unlock_irqrestore(&sq->lock, flags);

    return sset;
}
