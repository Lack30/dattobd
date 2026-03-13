// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 声明用于表示扇区区间及其链式组织方式的 sector_set 与 sset_list 类型。
 */

#ifndef SSET_LIST_H_
#define SSET_LIST_H_

#include <linux/types.h>

struct sector_set {
    struct sector_set *next;
    sector_t sect;
    unsigned int len;
};

struct sset_list {
    struct sector_set *head;
    struct sector_set *tail;
};

void sset_list_init(struct sset_list *sl);

int sset_list_empty(const struct sset_list *sl);

void sset_list_add(struct sset_list *sl, struct sector_set *sset);

struct sector_set *sset_list_pop(struct sset_list *sl);

#endif /* SSET_LIST_H_ */
