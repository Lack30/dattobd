// SPDX-License-Identifier: GPL-2.0-only

/*
 * 与 bio_list 结构操作相关的代码。
 *
 * Copyright (C) 2022 Datto Inc.
 */

#include "bio_list.h"

#ifndef HAVE_BIO_LIST
//#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)

/**
 * bio_list_empty() - 检查给定链表是否为空。
 * @bl: 链表。
 *
 * Return: 0 表示非空，非 0 表示空。
 */
int bio_list_empty(const struct bio_list *bl)
{
    return bl->head == NULL;
}

/**
 * bio_list_init() - 初始化链表以供使用。
 * @bl: 链表。
 */
void bio_list_init(struct bio_list *bl)
{
    bl->head = bl->tail = NULL;
}

/**
 * bio_list_add() - 在链表末尾添加元素。
 * @bl: 链表。
 * @bio: 要加入链表的元素。
 */
void bio_list_add(struct bio_list *bl, struct bio *bio)
{
    bio->bi_next = NULL;

    if (bl->tail)
        bl->tail->bi_next = bio;
    else
        bl->head = bio;

    bl->tail = bio;
}

/**
 * bio_list_pop() - 从链表取出一个元素。
 * @bl: 链表。
 *
 * 从 @bl 中移除一个元素并返回，按先进先出顺序。
 *
 * Return: 被移除的元素。
 */
struct bio *bio_list_pop(struct bio_list *bl)
{
    struct bio *bio = bl->head;

    if (bio) {
        bl->head = bl->head->bi_next;
        if (!bl->head)
            bl->tail = NULL;

        bio->bi_next = NULL;
    }

    return bio;
}

#endif
