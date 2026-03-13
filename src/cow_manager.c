// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 实现 COW 后备文件的映射缓存、索引读写、数据落盘与自动扩展逻辑。
 */

#include "cow_manager.h"
#include "filesystem.h"
#include "logging.h"
#include "tracer.h"
#include "blkdev.h"
#include "memory.h"

#ifdef HAVE_UUID_H
#include <linux/uuid.h>
#endif

#ifndef HAVE_VZALLOC
#define vzalloc(size) __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO, PAGE_KERNEL)
#endif

#define __cow_write_header_dirty(cm) __cow_write_header(cm, 0)
#define __cow_close_header(cm) __cow_write_header(cm, 1)
#define __cow_write_current_mapping(cm, pos) __cow_write_mapping(cm, pos, (cm)->curr_pos)

/* 内存相关宏 */
#define get_zeroed_pages(flags, order) __get_free_pages(((flags) | __GFP_ZERO), order)

const unsigned long dattobd_cow_ext_buf_size = sizeof(struct fiemap_extent) * 1024;

inline void __close_and_destroy_dattobd_mutable_file(struct dattobd_mutable_file *dfilp)
{
    file_close(dfilp);
    dattobd_mutable_file_unwrap(dfilp);
}

inline int __open_dattobd_mutable_file(const char *path, int flags,
                                       struct dattobd_mutable_file **dfilp)
{
    struct file *filp = NULL;
    int ret;

    ret = file_open(path, flags, &filp);

    if (ret) {
        LOG_ERROR(ret, "failed to open file");
        return ret;
    }

    *dfilp = dattobd_mutable_file_wrap(filp);

    if (IS_ERR(*dfilp)) {
        LOG_ERROR(-ENOMEM, "failed to wrap file pointer");
        __file_close_raw(filp);
        // filp 此处无需 kfree，由 filp_close 内部处理
        return -ENOMEM;
    }

    return 0;
}

/**
 * __cow_free_section() - 释放偏移 @sect_idx 处区段占用的内存并将该数组项标为未用。
 *
 * @cm: 跟踪块设备的 &struct cow_manager。
 * @sect_idx: COW 区段数组中的偏移。
 */
static void __cow_free_section(struct cow_manager *cm, unsigned long sect_idx)
{
    free_pages((unsigned long)cm->sects[sect_idx].mappings, cm->log_sect_pages);
    cm->sects[sect_idx].mappings = NULL;
    cm->allocated_sects--;
}

/**
 * __cow_alloc_section() - 在缓存中偏移 @sect_idx 处分配区段，标记为有数据并更新缓存统计。
 *
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 * @sect_idx: COW 区段索引。
 * @zero: 整数形式布尔值，1 表示映射初始化为零，0 表示可能为随机数据。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __cow_alloc_section(struct cow_manager *cm, unsigned long sect_idx, int zero)
{
    if (zero)
        cm->sects[sect_idx].mappings = (void *)get_zeroed_pages(GFP_KERNEL, cm->log_sect_pages);
    else
        cm->sects[sect_idx].mappings = (void *)__get_free_pages(GFP_KERNEL, cm->log_sect_pages);

    if (!cm->sects[sect_idx].mappings) {
        LOG_ERROR(-ENOMEM, "failed to allocate mappings at index %lu", sect_idx);
        return -ENOMEM;
    }

    cm->sects[sect_idx].has_data = 1;
    cm->allocated_sects++;

    return 0;
}

/**
 * __cow_load_section() - 分配并从 COW 后备文件读取指定区段。
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 * @sect_idx: COW 区段数组中的偏移。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __cow_load_section(struct cow_manager *cm, unsigned long sect_idx)
{
    int ret, i;
    int sect_size_bytes = COW_SECTION_SIZE * sizeof(uint64_t);

    ret = __cow_alloc_section(cm, sect_idx, 0);
    if (ret)
        goto error;

    for (i = 0; i < sect_size_bytes / COW_BLOCK_SIZE; i++) {
        ret = file_read(cm->dfilp, cm->dev, cm->sects[sect_idx].mappings,
                        cm->sect_size * sect_idx * 8 + COW_HEADER_SIZE, cm->sect_size * 8);
        if (ret)
            goto error;
    }

    return 0;

error:
    LOG_ERROR(ret, "error loading section from file");
    if (cm->sects[sect_idx].mappings)
        __cow_free_section(cm, sect_idx);
    return ret;
}

/**
 * __cow_write_section() - 将缓存的区段写回后备文件。
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 * @sect_idx: COW 区段数组中的偏移。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __cow_write_section(struct cow_manager *cm, unsigned long sect_idx)
{
    int i, ret;
    int sect_size_bytes = COW_SECTION_SIZE * sizeof(uint64_t);

    for (i = 0; i < sect_size_bytes / COW_BLOCK_SIZE; i++) {
        ret = file_write(cm->dfilp, cm->dev, cm->sects[sect_idx].mappings,
                         cm->sect_size * sect_idx * 8 + COW_HEADER_SIZE, cm->sect_size * 8);
        if (ret) {
            LOG_ERROR(ret, "error writing cow manager section to file");
            return ret;
        }
    }

    return 0;
}

/**
 * __cow_sync_and_free_sections() - 将 &struct cow_manager 中部分区段同步到文件并释放。
 *
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 * @thresh: 0 表示释放所有区段；非零时使用量小于等于该阈值的区段会被同步并释放。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __cow_sync_and_free_sections(struct cow_manager *cm, unsigned long thresh)
{
    int ret;
    unsigned long i;

    for (i = 0; i < cm->total_sects && (!thresh || cm->allocated_sects > cm->allowed_sects / 2);
         i++) {
        if (cm->sects[i].mappings && (!thresh || cm->sects[i].usage <= thresh)) {
            ret = __cow_write_section(cm, i);
            if (ret) {
                LOG_ERROR(ret, "error writing cow manager section %lu to file", i);
                return ret;
            }

            __cow_free_section(cm, i);
        }
        cm->sects[i].usage = 0;
    }

    return 0;
}

/**
 * __cow_cleanup_mappings() - 从 &struct cow_manager 中释放约一半的缓存区段。
 *
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __cow_cleanup_mappings(struct cow_manager *cm)
{
    unsigned long i;
    int ret;
    unsigned long granularity, thresh = 0;

    // 找出 cow manager 各区段的最大使用量
    for (i = 0; i < cm->total_sects; i++) {
        if (cm->sects[i].usage > thresh)
            thresh = cm->sects[i].usage;
    }

    // 求 cm 各区段使用量的（近似）中位数
    thresh /= 2;
    granularity = thresh;
    while (granularity > 0) {
        unsigned long less, greater;
        granularity = granularity >> 1;
        less = 0;
        greater = 0;
        for (i = 0; i < cm->total_sects; i++) {
            if (cm->sects[i].usage <= thresh)
                less++;
            else
                greater++;
        }

        if (greater > less)
            thresh += granularity;
        else if (greater < less)
            thresh -= granularity;
        else
            break;
    }

    // 释放使用量低于中位数的区段
    ret = __cow_sync_and_free_sections(cm, thresh);
    if (ret) {
        LOG_ERROR(ret, "error cleaning cow manager mappings");
        return ret;
    }

    return 0;
}

/**
 * __cow_write_header() - 将内存中的头部数据写回块设备上的 COW 文件头。
 *
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 * @is_clean: 表示 COW 文件是否已正确关闭。0 清除 COW_CLEAN 标志，非 0 设置该标志。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __cow_write_header(struct cow_manager *cm, int is_clean)
{
    int ret;
    struct cow_header ch;

    if (is_clean) {
        cm->flags |= (1 << COW_CLEAN);
        LOG_DEBUG("writing COW header CLEAN");
    } else {
        cm->flags &= ~(1 << COW_CLEAN);
        LOG_DEBUG("writing COW header DIRTY");
    }

    ch.magic = COW_MAGIC;
    ch.flags = cm->flags;
    ch.fpos = cm->curr_pos;
    ch.fsize = cm->file_size;
    ch.seqid = cm->seqid;
    memcpy(ch.uuid, cm->uuid, COW_UUID_SIZE);
    ch.version = cm->version;
    ch.nr_changed_blocks = cm->nr_changed_blocks;

    ret = file_write(cm->dfilp, cm->dev, &ch, 0, sizeof(struct cow_header));
    if (ret) {
        LOG_ERROR(ret, "error syncing cow manager header");
        return ret;
    }

    return 0;
}

/**
 * __cow_open_header() - 从 COW 文件开头读取并校验 &struct cow_header，再根据
 *                       &struct cow_manager 中的变更写回后备文件。
 *
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 * @index_only: 整数形式布尔值，表示 COW 文件应为增量模式还是快照模式。
 * @reset_vmalloc: 整数形式布尔值，表示是否清除 COW_VMALLOC_UPPER 标志；
 *                 cow_manager->sects 可能由不同分配器分配，该标志指示如何释放。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __cow_open_header(struct cow_manager *cm, int index_only, int reset_vmalloc)
{
    int ret;
    struct cow_header ch;

    ret = file_read(cm->dfilp, cm->dev, &ch, 0, sizeof(struct cow_header));
    if (ret)
        goto error;

    if (ch.magic != COW_MAGIC) {
        ret = -EINVAL;
        LOG_ERROR(-EINVAL, "bad magic number found in cow file: %lu", ((unsigned long)ch.magic));
        goto error;
    }

    if (!(ch.flags & (1 << COW_CLEAN))) {
        ret = -EINVAL;
        LOG_ERROR(-EINVAL, "cow file not left in clean state: %lu", ((unsigned long)ch.flags));
        goto error;
    }

    if (((ch.flags & (1 << COW_INDEX_ONLY)) && !index_only) ||
        (!(ch.flags & (1 << COW_INDEX_ONLY)) && index_only)) {
        ret = -EINVAL;
        LOG_ERROR(-EINVAL, "cow file not left in %s state: %lu",
                  ((index_only) ? "index only" : "data tracking"), (unsigned long)ch.flags);
        goto error;
    }

    LOG_DEBUG("cow header opened with file pos = %llu, seqid = %llu", ((unsigned long long)ch.fpos),
              (unsigned long long)ch.seqid);

    if (reset_vmalloc)
        cm->flags = ch.flags & ~(1 << COW_VMALLOC_UPPER);
    else
        cm->flags = ch.flags;

    cm->curr_pos = ch.fpos;
    cm->file_size = ch.fsize;
    cm->seqid = ch.seqid;
    memcpy(cm->uuid, ch.uuid, COW_UUID_SIZE);
    cm->version = ch.version;
    cm->nr_changed_blocks = ch.nr_changed_blocks;

    ret = __cow_write_header_dirty(cm);
    if (ret)
        goto error;

    return 0;

error:
    LOG_ERROR(ret, "error opening cow manager header");
    return ret;
}

/**
 * cow_free_members() - 释放 COW 状态跟踪内存并 unlink COW 后备文件。
 *
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 */
void cow_free_members(struct cow_manager *cm)
{
    if (cm->sects) {
        unsigned long i;
        for (i = 0; i < cm->total_sects; i++) {
            if (cm->sects[i].mappings)
                free_pages((unsigned long)cm->sects[i].mappings, cm->log_sect_pages);
        }

        if (cm->flags & (1 << COW_VMALLOC_UPPER))
            vfree(cm->sects);
        else
            kfree(cm->sects);

        cm->sects = NULL;
    }

    if (cm->dfilp) {
        file_unlink(cm->dfilp);
        __close_and_destroy_dattobd_mutable_file(cm->dfilp);
        cm->dfilp = NULL;
    }
}

/**
 * cow_free() - 释放 COW 跟踪所用内存并从块设备上 unlink COW 后备文件。
 *
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 */
void cow_free(struct cow_manager *cm)
{
    cow_free_members(cm);
    kfree(cm);
}

/**
 * cow_sync_and_free() - 将缓存刷写到后备文件、关闭 COW 文件并释放 &struct cow_manager。
 * @cm: 与 &struct snap_device 关联的 &struct cow_manager。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int cow_sync_and_free(struct cow_manager *cm)
{
    int ret;

    LOG_DEBUG("ENTER cow_sync_and_free");
    ret = __cow_sync_and_free_sections(cm, 0);
    if (ret)
        goto error;

    ret = __cow_close_header(cm);
    if (ret)
        goto error;

    if (cm->dfilp) {
        __close_and_destroy_dattobd_mutable_file(cm->dfilp);
        cm->dfilp = NULL;
    }

    if (cm->sects) {
        if (cm->flags & (1 << COW_VMALLOC_UPPER))
            vfree(cm->sects);
        else
            kfree(cm->sects);
    }

    kfree(cm);

    return 0;

error:
    LOG_ERROR(ret, "error while syncing and freeing cow manager");
    cow_free(cm);
    return ret;
}

/**
 * cow_sync_and_close() - 将缓存刷写到后备文件并关闭 COW 文件，但不释放 &struct cow_manager。
 * @cm: 与 &struct snap_device 关联的 &struct cow_manager。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int cow_sync_and_close(struct cow_manager *cm)
{
    int ret;

    LOG_DEBUG("ENTER cow_sync_and_close");

    ret = __cow_sync_and_free_sections(cm, 0);
    if (ret)
        goto error;

    ret = __cow_close_header(cm);
    if (ret)
        goto error;

    ret = cow_get_file_extents(cm->dev, cm->dfilp->filp);
    if (ret)
        goto error;

    if (cm->dfilp) {
        __close_and_destroy_dattobd_mutable_file(cm->dfilp);
        cm->dfilp = NULL;
    }

    return 0;

error:
    LOG_ERROR(ret, "error while syncing and closing cow manager");
    cow_free_members(cm);
    return ret;
}

/**
 * cow_reopen() - 重新打开位于 @pathname 的已有 COW 文件。
 *
 * @cm: 与 &struct snap_device 关联的 &struct cow_manager。
 * @pathname: COW 文件路径。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int cow_reopen(struct cow_manager *cm, const char *pathname)
{
    int ret;

    LOG_DEBUG("reopening cow file");
    ret = __open_dattobd_mutable_file(pathname, 0, &cm->dfilp);
    if (ret)
        goto error;

    LOG_DEBUG("opening cow header");
    ret = __cow_open_header(cm, (cm->flags & (1 << COW_INDEX_ONLY)), 0);
    if (ret)
        goto error;

    return 0;

error:
    LOG_ERROR(ret, "error reopening cow manager");
    if (cm->dfilp) {
        __close_and_destroy_dattobd_mutable_file(cm->dfilp);
        cm->dfilp = NULL;
    }

    return ret;
}

/**
 * __cow_calculate_allowed_sects() - 估算在允许的缓存大小内可容纳的 COW 区段总数。
 *
 * @cache_size: 缓存允许的字节数，至少应能容纳快照期间用于跟踪的 cow_section 数组。
 * @total_sects: 当前已分配的区段数。
 *
 * Return: 在预留缓存内存内还能容纳的区段数。
 */
static unsigned long __cow_calculate_allowed_sects(unsigned long cache_size,
                                                   unsigned long total_sects)
{
    if (cache_size <= (total_sects * sizeof(struct cow_section)))
        return 0;
    else
        return (cache_size - (total_sects * sizeof(struct cow_section))) / (COW_SECTION_SIZE * 8);
}

/**
 * cow_reload() - 分配 &struct cow_manager 并从指定 COW 文件重载；所有缓存区段标记为有数据，
 *                后续会从磁盘按需加载。
 * @path: COW 文件路径。
 * @elements: 通常为块设备扇区数。
 * @sect_size: &struct cow_manager 使用的基本区段大小。
 * @cache_size: 数据缓存占用的内存（字节）。
 * @index_only: 整数形式布尔值，表示 COW 为增量模式还是快照模式。
 * @cm_out: 重载得到的 &struct cow_manager 指针。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int cow_reload(const char *path, uint64_t elements, unsigned long sect_size,
               unsigned long cache_size, int index_only, struct cow_manager **cm_out)
{
    int ret;
    unsigned long i;
    struct cow_manager *cm;

    LOG_DEBUG("allocating cow manager");
    cm = kzalloc(sizeof(struct cow_manager), GFP_KERNEL);
    if (!cm) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating cow manager");
        goto error;
    }

    LOG_DEBUG("opening cow file");
    ret = __open_dattobd_mutable_file(path, 0, &cm->dfilp);
    if (ret)
        goto error;

    cm->allocated_sects = 0;
    cm->sect_size = sect_size;
    cm->log_sect_pages = get_order(sect_size * sizeof(uint64_t));
    cm->total_sects = NUM_SEGMENTS(elements, cm->log_sect_pages + PAGE_SHIFT - 3);
    cm->allowed_sects = __cow_calculate_allowed_sects(cache_size, cm->total_sects);
    cm->data_offset = COW_HEADER_SIZE + (cm->total_sects * (sect_size * sizeof(uint64_t)));
    cm->auto_expand = NULL;

    ret = __cow_open_header(cm, index_only, 1);
    if (ret)
        goto error;

    LOG_DEBUG("allocating cow manager array (%lu sections)", cm->total_sects);
    cm->sects = kzalloc((cm->total_sects) * sizeof(struct cow_section), GFP_KERNEL | __GFP_NOWARN);
    if (!cm->sects) {
        // 尝试改用 vmalloc
        cm->flags |= (1 << COW_VMALLOC_UPPER);
        cm->sects = vzalloc((cm->total_sects) * sizeof(struct cow_section));
        if (!cm->sects) {
            ret = -ENOMEM;
            LOG_ERROR(ret, "error allocating cow manager sects array");
            goto error;
        }
    }

    for (i = 0; i < cm->total_sects; i++) {
        cm->sects[i].has_data = 1;
    }

    *cm_out = cm;
    return 0;

error:
    LOG_ERROR(ret, "error during cow manager initialization");
    if (cm->dfilp) {
        __close_and_destroy_dattobd_mutable_file(cm->dfilp);
        cm->dfilp = NULL;
    }

    if (cm->sects) {
        if (cm->flags & (1 << COW_VMALLOC_UPPER))
            vfree(cm->sects);
        else
            kfree(cm->sects);
    }

    if (cm)
        kfree(cm);

    *cm_out = NULL;
    return ret;
}

/**
 * cow_init() - 分配并初始化 &struct cow_manager，在磁盘上创建 COW 后备文件并写入头部。
 * @dev: 保存快照设备状态的 &struct snap_device。
 * @path: COW 文件路径。
 * @elements: 通常为块设备扇区数。
 * @sect_size: &struct cow_manager 使用的基本区段大小。
 * @cache_size: 数据缓存占用的内存（字节）。
 * @file_max: COW 文件最大大小，创建后将预分配到此大小。
 * @uuid: NULL 或有效的 UUID 指针。
 * @seqid: 用于标识快照的序列 ID。
 * @cm_out: 初始化得到的 &struct cow_manager 指针。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int cow_init(struct snap_device *dev, const char *path, uint64_t elements, unsigned long sect_size,
             unsigned long cache_size, uint64_t file_max, const uint8_t *uuid, uint64_t seqid,
             struct cow_manager **cm_out)
{
    int ret;
    struct cow_manager *cm;

    LOG_DEBUG("allocating cow manager, seqid = %llu", (unsigned long long)seqid);
    cm = kzalloc(sizeof(struct cow_manager), GFP_KERNEL);
    if (!cm) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating cow manager");
        goto error;
    }

    LOG_DEBUG("creating cow file");
    ret = __open_dattobd_mutable_file(path, O_CREAT | O_TRUNC, &cm->dfilp);
    if (ret)
        goto error;

    cm->version = COW_VERSION_CHANGED_BLOCKS;
    cm->nr_changed_blocks = 0;
    cm->flags = 0;
    cm->allocated_sects = 0;
    cm->file_size = file_max;
    cm->sect_size = sect_size; // 区段可容纳的扇区数（存储侧），= 4096
    cm->seqid = seqid;
    // get_order(x)=ceil[log2(x/PAGE_SIZE)]；索引中一区段占的页数
    cm->log_sect_pages = get_order(sect_size * 8);
    cm->total_sects = NUM_SEGMENTS(elements, cm->log_sect_pages + PAGE_SHIFT - 3);
    // 除索引外缓存可容纳的区段数
    cm->allowed_sects = __cow_calculate_allowed_sects(cache_size, cm->total_sects);
    // 数据区偏移（字节），= 4096 + [total_sects*4096*8]（索引大小）
    cm->data_offset = COW_HEADER_SIZE + (cm->total_sects * (sect_size * 8));
    cm->curr_pos = cm->data_offset / COW_BLOCK_SIZE;
    cm->dev = dev;
    cm->auto_expand = NULL;

    if (uuid)
        memcpy(cm->uuid, uuid, COW_UUID_SIZE);
    else
        generate_random_uuid(cm->uuid);

    LOG_DEBUG("allocating cow manager array (%lu sections)", cm->total_sects);
    cm->sects = kzalloc((cm->total_sects) * sizeof(struct cow_section), GFP_KERNEL | __GFP_NOWARN);
    if (!cm->sects) {
        // 尝试改用 vmalloc
        cm->flags |= (1 << COW_VMALLOC_UPPER);
        cm->sects = vzalloc((cm->total_sects) * sizeof(struct cow_section));
        if (!cm->sects) {
            ret = -ENOMEM;
            LOG_ERROR(ret, "error allocating cow manager sects array");
            goto error;
        }
    }

    LOG_DEBUG("allocating cow file (%llu bytes)", (unsigned long long)file_max);
    ret = file_allocate(cm->dfilp, cm->dev, 0, file_max, NULL);
    if (ret)
        goto error;

    ret = __cow_write_header_dirty(cm);
    if (ret)
        goto error;

    *cm_out = cm;
    return 0;

error:
    LOG_ERROR(ret, "error during cow manager initialization");
    if (cm->dfilp) {
        file_unlink(cm->dfilp);
        __close_and_destroy_dattobd_mutable_file(cm->dfilp);
        cm->dfilp = NULL;
    }

    if (cm->sects) {
        if (cm->flags & (1 << COW_VMALLOC_UPPER))
            vfree(cm->sects);
        else
            kfree(cm->sects);
    }

    if (cm)
        kfree(cm);

    *cm_out = NULL;
    return ret;
}

/**
 * cow_truncate_to_index() - 将 COW 文件截断为仅包含头部和索引。
 *
 * @cm: 与 &struct snap_device 关联的 &struct cow_manager。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int cow_truncate_to_index(struct cow_manager *cm)
{
    int ret;

    // 将 COW 文件截断为仅含索引
    cm->flags |= (1 << COW_INDEX_ONLY);
    ret = file_truncate(cm->dfilp, cm->data_offset);

    if (!ret)
        cm->file_size = cm->data_offset;

    return ret;
}

/**
 * cow_modify_cache_size() - 修改 &struct cow_manager->allowed_sects。
 *
 * @cm: 与 &struct snap_device 关联的 &struct cow_manager。
 * @cache_size: 缓存允许的字节数，至少应能容纳快照期间 cow_section 数组所需内存。
 */
void cow_modify_cache_size(struct cow_manager *cm, unsigned long cache_size)
{
    cm->allowed_sects = __cow_calculate_allowed_sects(cache_size, cm->total_sects);
}

/**
 * cow_read_mapping() - 将区段加载到 &struct cow_manager 缓存；若超过允许区段数则清理缓存腾出空间。
 *
 * @cm: 与 &struct snap_device 关联的 &struct cow_manager。
 * @pos: 缓存内的区段索引偏移。
 * @out: 成功时输出该映射中存储的值。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int cow_read_mapping(struct cow_manager *cm, uint64_t pos, uint64_t *out)
{
    int ret;
    uint64_t sect_idx = pos;
    unsigned long sect_pos = do_div(sect_idx, cm->sect_size);

    cm->sects[sect_idx].usage++;

    if (!cm->sects[sect_idx].mappings) {
        if (!cm->sects[sect_idx].has_data) {
            *out = 0;
            return 0;
        } else {
            ret = __cow_load_section(cm, sect_idx);
            if (ret)
                goto error;
        }
    }

    *out = cm->sects[sect_idx].mappings[sect_pos];

    if (cm->allocated_sects > cm->allowed_sects) {
        ret = __cow_cleanup_mappings(cm);
        if (ret)
            goto error;
    }

    return 0;

error:
    LOG_ERROR(ret, "error reading cow mapping");
    return ret;
}

/**
 * __cow_write_mapping() - 将指定区段写入 COW 文件。
 *
 * @cm: 与 &struct snap_device 关联的 &struct cow_manager。
 * @pos: 缓存内的区段索引偏移。
 * @val: 要写入的映射值。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int __cow_write_mapping(struct cow_manager *cm, uint64_t pos, uint64_t val)
{
    int ret;
    uint64_t sect_idx = pos;
    unsigned long sect_pos = do_div(sect_idx, cm->sect_size);
    // do_div 将 sect_idx 改为 pos/cm->sect_size 的商，返回余数

    cm->sects[sect_idx].usage++;

    if (!cm->sects[sect_idx].mappings) {
        if (!cm->sects[sect_idx].has_data) {
            ret = __cow_alloc_section(cm, sect_idx, 1);
            if (ret)
                goto error;
        } else {
            ret = __cow_load_section(cm, sect_idx);
            if (ret)
                goto error;
        }
    }

    if (cm->version >= COW_VERSION_CHANGED_BLOCKS && !cm->sects[sect_idx].mappings[sect_pos])
        cm->nr_changed_blocks++;

    cm->sects[sect_idx].mappings[sect_pos] = val;

    if (cm->allocated_sects > cm->allowed_sects) {
        ret = __cow_cleanup_mappings(cm);
        if (ret)
            goto error;
    }

    return 0;

error:
    LOG_ERROR(ret, "error writing cow mapping");
    return ret;
}

/**
 * __cow_write_data() - 在 COW 文件当前偏移处写入一块 COW 数据。
 *
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 * @buf: 至少 COW_BLOCK_SIZE 大小的缓冲区。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int __cow_write_data(struct cow_manager *cm, void *buf)
{
    int ret;
    char *abs_path = NULL;
    int abs_path_len;
    uint64_t curr_size = cm->curr_pos * COW_BLOCK_SIZE;
    uint64_t expand_allowance = 0;
    int kstatfs_ret;
    struct kstatfs kstatfs;

retry:
    if (curr_size >= cm->file_size) {
        // 尝试扩展 COW 文件
        if (cm->auto_expand) {
            kstatfs_ret = 0;
            if (cm->dev && cm->dev->sd_base_dev) {
                kstatfs_ret = dattobd_get_kstatfs(cm->dev->sd_base_dev->bdev, &kstatfs);
            }

            if (!kstatfs_ret) {
                expand_allowance = cow_auto_expand_manager_get_allowance(
                        cm->auto_expand, kstatfs.f_bavail, (uint64_t)kstatfs.f_bsize);
            } else {
                LOG_WARN(
                        "failed to get kstatfs with error code %d, expansion allowance is given only if reserved space is 0.",
                        kstatfs_ret);
                expand_allowance =
                        cow_auto_expand_manager_get_allowance_free_unknown(cm->auto_expand);
            }

            if (expand_allowance) {
                ret = tracer_expand_cow_file_no_check(cm->dev, expand_allowance);
                expand_allowance = 0;
                if (ret)
                    goto error;
                goto retry;
            }
        }

        ret = -EFBIG;

        file_get_absolute_pathname(cm->dfilp, &abs_path, &abs_path_len);
        if (!abs_path) {
            LOG_ERROR(ret, "cow file max size exceeded (%llu/%llu)", curr_size, cm->file_size);
        } else {
            LOG_ERROR(ret, "cow file '%s' max size exceeded (%llu/%llu)", abs_path, curr_size,
                      cm->file_size);
            kfree(abs_path);
        }

        goto error;
    }

    ret = file_write(cm->dfilp, cm->dev, buf, curr_size, COW_BLOCK_SIZE);
    if (ret)
        goto error;

    cm->curr_pos++;

    return 0;

error:
    LOG_ERROR(ret, "error writing cow data");
    return ret;
}

/**
 * cow_write_current() - 按需将 @buf 中的 @block 数据写入 COW 存储；若该块已有数据则跳过以免覆盖快照数据，
 *                       未存在时同时写入映射与数据。
 *
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 * @block: 与 @buf 中数据对应的块号。
 * @buf: 属于 @block 的数据。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int cow_write_current(struct cow_manager *cm, uint64_t block, void *buf)
{
    int ret;
    uint64_t block_mapping;

    // 从 cow manager 读取该块映射
    ret = cow_read_mapping(cm, block, &block_mapping);
    if (ret)
        goto error;

    // 若块映射已存在则直接返回以免覆盖
    if (block_mapping)
        return 0;

    // 写入映射
    ret = __cow_write_current_mapping(cm, block);
    if (ret)
        goto error;

    // 写入数据
    ret = __cow_write_data(cm, buf);
    if (ret)
        goto error;

    return 0;

error:
    LOG_ERROR(ret, "error writing cow data and mapping");
    return ret;
}

/**
 * cow_read_data() - 从 COW 文件读取数据。
 *
 * @cm: 每个 &struct snap_device 对应一个 &struct cow_manager。
 * @buf: 至少 @len 字节的缓冲区。
 * @block_pos: 读取的块位置。
 * @block_off: 块内偏移，可小于一个完整 COW 块。
 * @len: 在该位置要读取的字节数。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int cow_read_data(struct cow_manager *cm, void *buf, uint64_t block_pos, unsigned long block_off,
                  unsigned long len)
{
    int ret;

    if (block_off >= COW_BLOCK_SIZE)
        return -EINVAL;

    ret = file_read(cm->dfilp, cm->dev, buf, (block_pos * COW_BLOCK_SIZE) + block_off, len);
    if (ret) {
        LOG_ERROR(ret, "error reading cow data");
        return ret;
    }

    return 0;
}

int cow_get_file_extents(struct snap_device *dev, struct file *filp)
{
    int ret;
    struct fiemap_extent_info fiemap_info;
    unsigned int fiemap_mapped_extents_size, i_ext;
    struct fiemap_extent *extent;
    char parent_process_name[TASK_COMM_LEN];
    unsigned long vm_flags = VM_READ | VM_WRITE;
    unsigned long start_addr;
    struct task_struct *task;
    struct vm_area_struct *vma;
    struct page *pg;
    __user uint8_t *cow_ext_buf;

    unsigned long cow_ext_buf_size = ALIGN(dattobd_cow_ext_buf_size, PAGE_SIZE);

    int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64 start, u64 len);

    int (*insert_vm_struct)(struct mm_struct * mm, struct vm_area_struct * vma) =
            (INSERT_VM_STRUCT_ADDR != 0) ?
                    (int (*)(struct mm_struct * mm, struct vm_area_struct * vma))(
                            INSERT_VM_STRUCT_ADDR +
                            (long long)(((void *)kfree) - (void *)KFREE_ADDR)) :
                    NULL;

    if (!insert_vm_struct) {
        LOG_ERROR(-ENOTSUPP, "insert_vm_struct() was not found");
        return -ENOTSUPP;
    }

    fiemap = NULL;
    task = get_current();

    LOG_DEBUG("getting cow file extents from filp=%p", filp);
    LOG_DEBUG("attempting page stealing from %s", get_task_comm(parent_process_name, task));

    dattobd_mm_lock(task->mm);
    start_addr = get_unmapped_area(NULL, 0, cow_ext_buf_size, 0, VM_READ | VM_WRITE);

    if (IS_ERR_VALUE(start_addr))
        return start_addr; // returns -EPERM if failed

    vma = dattobd_vm_area_allocate(task->mm);

    if (!vma) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "vm_area_alloc() failed");
        dattobd_mm_unlock(task->mm);
        return ret;
    }

    vma->vm_start = start_addr;
    vma->vm_end = start_addr + cow_ext_buf_size;
    *(unsigned long *)&vma->vm_flags = vm_flags;
    vma->vm_page_prot = vm_get_page_prot(vm_flags);
    vma->vm_pgoff = 0;

    ret = insert_vm_struct(task->mm, vma);
    if (ret < 0) {
        LOG_ERROR(ret, "insert_vm_struct() failed");
        dattobd_vm_area_free(vma);
        dattobd_mm_unlock(task->mm);
        return ret;
    }

    pg = alloc_pages(GFP_USER, get_order(cow_ext_buf_size));
    if (!pg) {
        LOG_ERROR(ret, "alloc_page() failed");
        dattobd_vm_area_free(vma);
        dattobd_mm_unlock(task->mm);
        return ret;
    }

    SetPageReserved(pg);
    ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(pg), cow_ext_buf_size, PAGE_SHARED);
    if (ret < 0) {
        LOG_ERROR(ret, "remap_pfn_range() failed");
        ClearPageReserved(pg);
        __free_pages(pg, get_order(cow_ext_buf_size));
        dattobd_vm_area_free(vma);
        dattobd_mm_unlock(task->mm);
        return ret;
    }

    cow_ext_buf = (__user uint8_t *)start_addr;

    if (filp->f_inode->i_op)
        fiemap = filp->f_inode->i_op->fiemap;

    if (fiemap) {
        int64_t fiemap_max = ~0ULL & ~(1ULL << 63);
        int max_num_extents =
                cow_ext_buf_size; // used for do_div() as it overwrites the first argument

        fiemap_info.fi_flags = FIEMAP_FLAG_SYNC;
        fiemap_info.fi_extents_mapped = 0;
        do_div(max_num_extents, sizeof(struct fiemap_extent));
        fiemap_info.fi_extents_max = max_num_extents;
        fiemap_info.fi_extents_start = (struct fiemap_extent __user *)cow_ext_buf;

        ret = fiemap(filp->f_inode, &fiemap_info, 0, fiemap_max);

        LOG_DEBUG("fiemap for cow file (ret %d), extents %u (max %u)", ret,
                  fiemap_info.fi_extents_mapped, fiemap_info.fi_extents_max);

        if (!ret && fiemap_info.fi_extents_mapped > 0) {
            if (dev->sd_cow_extents)
                kfree(dev->sd_cow_extents);
            fiemap_mapped_extents_size =
                    fiemap_info.fi_extents_mapped * sizeof(struct fiemap_extent);
            dev->sd_cow_extents = kmalloc(fiemap_mapped_extents_size, GFP_KERNEL);
            if (dev->sd_cow_extents) {
                //TODO: closely watch
                ret = copy_from_user(dev->sd_cow_extents, cow_ext_buf, fiemap_mapped_extents_size);
                if (!ret) {
                    dev->sd_cow_ext_cnt = fiemap_info.fi_extents_mapped;
                    WARN(dev->sd_cow_ext_cnt == max_num_extents,
                         "max num of extents read, increase cow_ext_buf_size");
                    extent = dev->sd_cow_extents;
                    for (i_ext = 0; i_ext < fiemap_info.fi_extents_mapped; ++i_ext, ++extent) {
                        LOG_DEBUG("   cow file extent: log 0x%llx, phy 0x%llx, len %llu",
                                  extent->fe_logical, extent->fe_physical, extent->fe_length);
                    }
                }
            }
        }
    } else {
        ret = -ENOTSUPP;
        LOG_ERROR(ret, "fiemap not supported");
        goto out;
    }

out:
    ClearPageReserved(pg);
    dattobd_mm_unlock(task->mm);
    vm_munmap(vma->vm_start, cow_ext_buf_size);
    __free_pages(pg, get_order(cow_ext_buf_size));
    return ret;
}

int __cow_expand_datastore(struct cow_manager *cm, uint64_t append_size_bytes)
{
    int ret;
    uint64_t actual = 0;

    LOG_DEBUG("trying to expand cow file with %llu bytes", append_size_bytes);

    ret = file_allocate(cm->dfilp, cm->dev, cm->file_size, append_size_bytes, &actual);

    if (actual != append_size_bytes) {
        LOG_WARN("cow file was not expanded to requested size (req: %llu, act: %llu)",
                 append_size_bytes, actual);
    }

    cm->file_size = cm->file_size + actual;

    if (ret) {
        LOG_ERROR(ret, "unable to expand cow file");
        return ret;
    }

    return 0;
}

struct cow_auto_expand_manager *cow_auto_expand_manager_init(void)
{
    struct cow_auto_expand_manager *aem =
            kzalloc(sizeof(struct cow_auto_expand_manager), GFP_KERNEL);
    if (!aem) {
        LOG_ERROR(-ENOMEM, "error allocating cow auto expand manager");
        return ERR_PTR(-ENOMEM);
    }

    mutex_init(&aem->lock);

    return aem;
}

int cow_auto_expand_manager_reconfigure(struct cow_auto_expand_manager *aem, uint64_t step_size_mib,
                                        uint64_t reserved_space_mib)
{
    mutex_lock(&aem->lock);
    aem->step_size_mib = step_size_mib;
    aem->reserved_space_mib = reserved_space_mib;
    mutex_unlock(&aem->lock);
    return 0;
}

/*
* cow_auto_expand_manager_get_allowance() - Tests if the auto expand manager has steps remaining regarding to the available blocks and block size.
*
* @aem: The &struct cow_auto_expand_manager.
* @available_blocks: The number of available blocks on the block device. (from kstatfs, f_bavail)
* @block_size: The size of a block on the block device. (from kstatfs, f_bsize)
*
* Return:
* 0 - no steps remaining
* !0 - size to expand the cow file by
*/
uint64_t cow_auto_expand_manager_get_allowance(struct cow_auto_expand_manager *aem,
                                               uint64_t available_blocks, uint64_t block_size_bytes)
{
#define ceil(a, b) (((a) + (b)-1) / (b))
#define mib_to_bytes(a) ((a)*1024 * 1024)

    uint64_t ret;

    ret = 0;
    mutex_lock(&aem->lock);
    if (aem->step_size_mib && ceil(mib_to_bytes(aem->step_size_mib + aem->reserved_space_mib),
                                   block_size_bytes) <= available_blocks) {
        ret = mib_to_bytes(aem->step_size_mib);
    } else {
        if (aem->step_size_mib) {
            LOG_WARN(
                    "rejected auto-expand: %llu MiB step size, %llu MiB reserved space, %llu blocks available, %llu B block size",
                    aem->step_size_mib, aem->reserved_space_mib, available_blocks,
                    block_size_bytes);
        }
    }
    mutex_unlock(&aem->lock);

    return ret;
}

/*
* cow_auto_expand_manager_get_allowance_free_unknown() - Tests if the auto expand manager has steps remaining if the free space is not available.
* Allows to make an auto-expand if the reserved space is 0.
*
* @aem: The &struct cow_auto_expand_manager.
*
* Return:
* 0 - no steps remaining
* !0 - size to expand the cow file by
*/
uint64_t cow_auto_expand_manager_get_allowance_free_unknown(struct cow_auto_expand_manager *aem)
{
#define mib_to_bytes(a) ((a)*1024 * 1024)

    uint64_t ret;

    ret = 0;
    mutex_lock(&aem->lock);
    // 仅在保留空间为 0 时允许在可用空间未知的情况下进行 COW 文件自动扩展
    if (aem->step_size_mib && aem->reserved_space_mib == 0) {
        ret = mib_to_bytes(aem->step_size_mib);
    }
    mutex_unlock(&aem->lock);

    return ret;
}

void cow_auto_expand_manager_free(struct cow_auto_expand_manager *aem)
{
    mutex_destroy(&aem->lock);
    kfree(aem);
}
