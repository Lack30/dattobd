// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#ifndef COW_MANAGER_H_
#define COW_MANAGER_H_

#include "dattobd.h"
#include "filesystem.h"

#ifndef __KERNEL__
#include <stdint.h>
#endif

#define COW_SECTION_SIZE (1 << PAGE_SHIFT)

#define cow_write_filler_mapping(cm, pos) __cow_write_mapping(cm, pos, 1)
extern const unsigned long dattobd_cow_ext_buf_size;

/**
 * struct cow_section - COW 区段的数据与使用统计。
 *
 * &struct cow_section 是 COW 管理器的基本数据单元，一个区段对应 4K 扇区。
 */
struct cow_section {
    char has_data;           // 本区段有映射（文件或内存）时非零
    unsigned long usage;     // 本区段使用次数计数
    uint64_t *mappings;      // 块地址数组
};

/* 当前重载时不保留自动扩展设置 */
struct cow_auto_expand_manager {
    struct mutex lock;

    uint64_t step_size_mib;
    uint64_t reserved_space_mib;
};

struct cow_manager {
    struct dattobd_mutable_file *dfilp; // cow manager 写入的目标文件
    uint32_t flags;                      // cow manager 当前状态标志
    uint64_t curr_pos;                  // 当前写头位置
    uint64_t data_offset;               // 数据区起始偏移
    uint64_t file_size;                 // 当前文件大小；超限前报错或触发扩展
    uint64_t seqid;                    // 序列 id，每次切回快照模式时递增
    uint64_t version;                  // COW 文件格式版本
    uint64_t nr_changed_blocks;        // 自上次快照以来变更块数
    uint8_t uuid[COW_UUID_SIZE];       // 本系列快照的 uuid
    unsigned int log_sect_pages;       // 存储一区段所需页数的 log2
    unsigned long sect_size;           // 区段可容纳元素个数
    unsigned long allocated_sects;    // 当前已分配区段数
    unsigned long total_sects;         // cm 日志对应的区段总数
    unsigned long allowed_sects;       // 允许同时分配的最大区段数
    struct cow_section *sects;         // 映射区段数组指针
    struct snap_device *dev;           // 快照设备指针

    struct cow_auto_expand_manager *auto_expand; // 自动扩展设置
};

/***************************COW MANAGER FUNCTIONS**************************/

void cow_free_members(struct cow_manager *cm);

void cow_free(struct cow_manager *cm);

int cow_sync_and_free(struct cow_manager *cm);

int cow_sync_and_close(struct cow_manager *cm);

int cow_reopen(struct cow_manager *cm, const char *pathname);

int cow_reload(const char *path, uint64_t elements, unsigned long sect_size,
               unsigned long cache_size, int index_only, struct cow_manager **cm_out);

int cow_init(struct snap_device *dev, const char *path, uint64_t elements, unsigned long sect_size,
             unsigned long cache_size, uint64_t file_max, const uint8_t *uuid, uint64_t seqid,
             struct cow_manager **cm_out);

int cow_truncate_to_index(struct cow_manager *cm);

void cow_modify_cache_size(struct cow_manager *cm, unsigned long cache_size);

int cow_read_mapping(struct cow_manager *cm, uint64_t pos, uint64_t *out);

int cow_write_current(struct cow_manager *cm, uint64_t block, void *buf);

int cow_read_data(struct cow_manager *cm, void *buf, uint64_t block_pos, unsigned long block_off,
                  unsigned long len);

int __cow_write_mapping(struct cow_manager *cm, uint64_t pos, uint64_t val);

int cow_get_file_extents(struct snap_device *dev, struct file *filp);

int __cow_expand_datastore(struct cow_manager *cm, uint64_t append_size_bytes);

struct cow_auto_expand_manager *cow_auto_expand_manager_init(void);

int cow_auto_expand_manager_reconfigure(struct cow_auto_expand_manager *aem, uint64_t step_size_mib,
                                        uint64_t reserved_space_mib);

uint64_t cow_auto_expand_manager_get_allowance(struct cow_auto_expand_manager *aem,
                                               uint64_t available_blocks,
                                               uint64_t block_size_bytes);

uint64_t cow_auto_expand_manager_get_allowance_free_unknown(struct cow_auto_expand_manager *aem);

void cow_auto_expand_manager_free(struct cow_auto_expand_manager *aem);

#endif /* COW_MANAGER_H_ */
