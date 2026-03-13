// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "callback_refs.h"

#ifndef USE_BDOPS_SUBMIT_BIO

struct mrf_tracking_data {
    const struct gendisk *mtd_disk;
    BIO_REQUEST_CALLBACK_FN *mtd_orig;
    atomic_t mtd_count;
    struct hlist_node node;
};

#define MAX_BUCKETS_BITS 2 // 2^2 = 4 个桶
DEFINE_HASHTABLE(mrf_tracking_map, MAX_BUCKETS_BITS);

void mrf_tracking_init(void)
{
    hash_init(mrf_tracking_map);
}

static struct mrf_tracking_data *get_a_node(const struct gendisk *disk)
{
    unsigned int bkt = 0;
    struct mrf_tracking_data *cur = NULL;
    hash_for_each (mrf_tracking_map, bkt, cur, node) {
        if (cur->mtd_disk == disk) {
            return cur;
        }
    }
    return NULL;
}

int mrf_get(const struct gendisk *disk, BIO_REQUEST_CALLBACK_FN *fn)
{
    struct mrf_tracking_data *mtd = get_a_node(disk);
    if (!mtd) {
        mtd = kzalloc(sizeof(struct mrf_tracking_data), GFP_KERNEL);
        if (!mtd) {
            return -ENOMEM;
        }
        mtd->mtd_disk = disk;
        mtd->mtd_orig = (BIO_REQUEST_CALLBACK_FN *)fn;
        // kzalloc 保证 mtd->mtd_count 已为零
        hash_add(mrf_tracking_map, &mtd->node, (unsigned long)disk);
    }

    atomic_inc(&mtd->mtd_count);

    return 0;
}

const BIO_REQUEST_CALLBACK_FN *mrf_put(struct gendisk *disk)
{
    BIO_REQUEST_CALLBACK_FN *fn = NULL;
    struct mrf_tracking_data *mtd = get_a_node(disk);
    if (!mtd) {
        return NULL; // 此处可改为返回错误，相当于双重释放
    }

    fn = mtd->mtd_orig;
    if (atomic_dec_and_test(&mtd->mtd_count)) { // mtd_count 减到零时
        hash_del(&mtd->node);
        kfree(mtd);
        return (const BIO_REQUEST_CALLBACK_FN *)fn; // 最后一次引用时返回原函数指针
    }

    // 返回当前 mrf，便于交换逻辑处理
    return (const BIO_REQUEST_CALLBACK_FN *)GET_BIO_REQUEST_TRACKING_PTR_GD(disk);
}

#endif
