// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 实现 sector_set 链表的初始化、判空、尾插和头弹出操作。
 */

#include "sset_list.h"

/**
 * sset_list_init() - 初始化 @sl 链表。
 *
 * @sl: &struct sset_list 对象指针。
 */
inline void sset_list_init(struct sset_list *sl)
{
    sl->head = sl->tail = NULL;
}

/**
 * sset_list_empty() - 检查 &struct sset_list 是否为空。
 *
 * @sl: &struct sset_list 对象指针。
 *
 * Return: 空时为 0，否则非 0。
 */
inline int sset_list_empty(const struct sset_list *sl)
{
    return sl->head == NULL;
}

/**
 * sset_list_add() - 将 @sset 加入链表 @sl 的尾部。
 *
 * @sl: &struct sset_list 对象指针。
 * @sset: 要加入 @sl 的 &struct sector_set 对象指针。
 */
void sset_list_add(struct sset_list *sl, struct sector_set *sset)
{
    sset->next = NULL;
    if (sl->tail)
        sl->tail->next = sset;
    else
        sl->head = sset;
    sl->tail = sset;
}

/**
 * sset_list_pop() - 从 @sl 头部取出一个元素（并从链表中移除）。
 *
 * @sl: &struct sset_list 对象指针。
 *
 * Return: 链表头元素，空时返回 NULL。
 */
struct sector_set *sset_list_pop(struct sset_list *sl)
{
    struct sector_set *sset = sl->head;

    if (sset) {
        sl->head = sl->head->next;
        if (!sl->head)
            sl->tail = NULL;
        sset->next = NULL;
    }

    return sset;
}
