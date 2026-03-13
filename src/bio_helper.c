// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022-2023 Datto Inc.
 */

#include "includes.h"

#include "bio_helper.h"
#include "logging.h"
#include "snap_device.h"
#include "tracer_helper.h"
#include "tracing_params.h"
#include <linux/bio.h>
#ifdef HAVE_BIO_BLKG
#include <linux/blk-cgroup.h>
#endif

/**
 * dattobd_bio_get_queue() - 获取给定块 I/O 操作对应的请求队列。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 *
 * Return: 包含该 @bio 的 request_queue。
 */
struct request_queue *dattobd_bio_get_queue(struct bio *bio)
{
#ifdef HAVE_BIO_BI_BDEV
    //#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    return bdev_get_queue(bio->bi_bdev);
#else
    return bio->bi_disk->queue;
#endif
}

/**
 * dattobd_bio_set_dev() - 设置与该块 I/O 操作关联的块设备。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @bdev: 关联的块设备。
 */
void dattobd_bio_set_dev(struct bio *bio, struct block_device *bdev)
{
#ifdef HAVE_BIO_BI_BDEV
    //#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    bio->bi_bdev = bdev;
#else
    bio_set_dev(bio, bdev);
#endif
}

/**
 * dattobd_bio_copy_dev() - 将块 I/O 的块设备从 @src 复制到 @dst。
 * @src: 源 bio。
 * @dst: 目标 bio。
 */
void dattobd_bio_copy_dev(struct bio *dst, struct bio *src)
{
#ifdef HAVE_BIO_BI_BDEV
    //#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    dst->bi_bdev = src->bi_bdev;
#else
    bio_copy_dev(dst, src);
#endif
}

#ifndef REQ_WRITE
#define REQ_WRITE WRITE
#endif

#ifndef REQ_FLUSH
#define REQ_FLUSH (1 << BIO_RW_BARRIER)
#endif

/* 若未定义则表示内核不支持 */
#ifndef REQ_SECURE
#define REQ_SECURE 0
#endif

#ifndef REQ_WRITE_SAME
#define REQ_WRITE_SAME 0
#endif

#ifndef HAVE_SUBMIT_BIO_1
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)

#ifndef HAVE_ENUM_REQ_OP
/**
 * dattobd_set_bio_ops() - 设置 @bio 的 I/O 操作类型及附加标志。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @op: 要执行的操作。
 * @op_flags: 附加标志。
 */
void dattobd_set_bio_ops(struct bio *bio, req_op_t op, unsigned op_flags)
{
    bio->bi_rw = 0;

    switch (op) {
    case REQ_OP_READ:
        break;
    case REQ_OP_WRITE:
        bio->bi_rw |= REQ_WRITE;
        break;
    case REQ_OP_DISCARD:
        bio->bi_rw |= REQ_DISCARD;
        break;
    case REQ_OP_SECURE_ERASE:
        bio->bi_rw |= REQ_DISCARD | REQ_SECURE;
        break;
    case REQ_OP_WRITE_SAME:
        bio->bi_rw |= REQ_WRITE_SAME;
        break;
    case REQ_OP_FLUSH:
        bio->bi_rw |= REQ_FLUSH;
        break;
    }

    bio->bi_rw |= op_flags;
}
#endif

#if !defined(HAVE_BIO_BI_OPF) && defined(HAVE_ENUM_REQ_OP)
void dattobd_set_bio_ops(struct bio *bio, req_op_t op, unsigned op_flags)
{
    bio->bi_rw = 0;
    bio->bi_rw |= op;
}
#endif
/**
 * dattobd_bio_op_flagged() - 检查 bio 是否包含指定标志。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @flag: 要检查的操作标志。
 *
 * Return: 0 表示未设置，非 0 表示已设置。
 */
int dattobd_bio_op_flagged(struct bio *bio, unsigned int flag)
{
    return bio->bi_rw & flag;
}

/**
 * dattobd_bio_op_set_flag() - 在 bio I/O 操作标志字段中设置指定标志。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @flag: 要设置的标志。
 */
void dattobd_bio_op_set_flag(struct bio *bio, unsigned int flag)
{
    bio->bi_rw |= flag;
}

/**
 * dattobd_bio_op_clear_flag() - 清除 bio I/O 操作标志字段中的指定标志。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @flag: 要清除的标志。
 */
void dattobd_bio_op_clear_flag(struct bio *bio, unsigned int flag)
{
    bio->bi_rw &= ~flag;
}
#else

#ifndef HAVE_ENUM_REQ_OPF
//#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
typedef enum req_op req_op_t;
#else
typedef enum req_opf req_op_t;
#endif

/**
 * dattobd_set_bio_ops() - 设置 bio 的操作类型及标志。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @op: 要执行的操作。
 * @op_flags: 附加标志。
 */
void dattobd_set_bio_ops(struct bio *bio, req_op_t op, unsigned op_flags)
{
    bio->bi_opf = 0;
    bio->bi_opf = op | op_flags;
}

/**
 * dattobd_bio_op_flagged() - 检查 bio 是否包含指定标志。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @flag: 要检查的操作标志。
 *
 * Return: 0 表示未设置，非 0 表示已设置。
 */
int dattobd_bio_op_flagged(struct bio *bio, unsigned int flag)
{
    return bio->bi_opf & flag;
}

/**
 * dattobd_bio_op_set_flag() - 在 bio I/O 操作标志字段中设置指定标志。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @flag: 要设置的标志。
 */
void dattobd_bio_op_set_flag(struct bio *bio, unsigned int flag)
{
    bio->bi_opf |= flag;
}

/**
 * dattobd_bio_op_clear_flag() - 清除 bio I/O 操作标志字段中的指定标志。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @flag: 要清除的标志。
 */
void dattobd_bio_op_clear_flag(struct bio *bio, unsigned int flag)
{
    bio->bi_opf &= ~flag;
}

#endif

#if !defined HAVE_SUBMIT_BIO_WAIT && !defined HAVE_SUBMIT_BIO_1
//#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
struct submit_bio_ret {
    struct completion event;
    int error;
};

/**
 * __submit_bio_wait_endio() - 各内核版本共用的 endio 完成例程。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @error: 错误码（errno）。
 */
static void __submit_bio_wait_endio(struct bio *bio, int error)
{
    struct submit_bio_ret *ret = bio->bi_private;
    ret->error = error;
    complete(&ret->event);
}

#ifdef HAVE_BIO_ENDIO_INT

/**
 * submit_bio_wait_endio() - 用作 &struct bio 的 I/O 结束例程。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @bytes: 未使用。
 * @error: 错误码（errno）。
 *
 * Return: 0 表示整个 bio 的 I/O 已结束，1 表示该 bio 还有剩余字节。
 */
static int submit_bio_wait_endio(struct bio *bio, unsigned int bytes, int error)
{
    if (bio->bi_size)
        return 1;

    __submit_bio_wait_endio(bio, error);
    return 0;
}

#else

/**
 * submit_bio_wait_endio() - 用作 &struct bio 的 I/O 结束例程。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @error: 错误码（errno）。
 */
static void submit_bio_wait_endio(struct bio *bio, int error)
{
    __submit_bio_wait_endio(bio, error);
}

#endif

/**
 * submit_bio_wait() - 提交 bio 并等待其完成。
 *
 * @rw: 标志（如 READ、WRITE 或 READA 预读）。
 * @bio: 描述此次 I/O 的 &struct bio。
 *
 * Return: 0 表示成功，非 0 为表示错误的 errno。
 */
int submit_bio_wait(int rw, struct bio *bio)
{
    struct submit_bio_ret ret;

    // 内核实现中有 rw |= REQ_SYNC，但我们所有调用处已设置且该写法随内核版本变化

    init_completion(&ret.event);
    bio->bi_private = &ret;
    bio->bi_end_io = submit_bio_wait_endio;
    submit_bio(rw, bio);
    wait_for_completion(&ret.event);

    return ret.error;
}

#endif

#ifdef HAVE_BIO_ENDIO_INT

/**
 * dattobd_bio_endio() - 结束 bio 的 I/O。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @err: 错误码（errno）。
 */
void dattobd_bio_endio(struct bio *bio, int err)
{
    bio_endio(bio, bio->bi_size, err);
}

#elif !defined HAVE_BIO_ENDIO_1

/**
 * dattobd_bio_endio() - 结束 bio 的 I/O。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @err: 错误码（errno）。
 */
void dattobd_bio_endio(struct bio *bio, int err)
{
    bio_endio(bio, err);
}

#elif defined HAVE_BLK_STATUS_T

/**
 * dattobd_bio_endio() - 结束 bio 的 I/O。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @err: 错误码（errno）。
 */
void dattobd_bio_endio(struct bio *bio, int err)
{
    bio->bi_status = errno_to_blk_status(err);
    bio_endio(bio);
}

#else

/**
 * dattobd_bio_endio() - 结束 bio 的 I/O。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @err: 错误码（errno）。
 */
void dattobd_bio_endio(struct bio *bio, int err)
{
    bio->bi_error = err;
    bio_endio(bio);
}

#endif

/**
 * __on_bio_read_complete() - &struct bio 的 I/O 完成时执行的私有完成例程。
 * @bio: 描述此次 I/O 的 &struct bio。
 * @err: 错误码（errno）。
 *
 * 当收到写请求且需要 COW 时，先将写 BIO 克隆为读 BIO，本函数作为克隆 BIO 的完成例程；
 * 完成后将该 BIO 交给 COW 线程继续处理。
 */
static void __on_bio_read_complete(struct bio *bio, int err)
{
    int ret;
    struct tracing_params *tp = bio->bi_private;
    struct snap_device *dev = tp->dev;
    struct bio_sector_map *map = NULL;
#ifndef HAVE_BVEC_ITER
    unsigned short i = 0;
#endif

    // 检查读错误
    if (err) {
        ret = err;
        LOG_ERROR(ret, "error reading from base device for copy on write");
        goto error;
    }

    // 将 bio 改为写 bio
    dattobd_set_bio_ops(bio, REQ_OP_WRITE, 0);
    bio->bi_end_io = NULL;

    // 将 bio 迭代器恢复为原始状态
    for (map = tp->bio_sects.head; map != NULL && map->bio != NULL; map = map->next) {
        if (bio == map->bio) {
            bio_sector(bio) = map->sect - dev->sd_sect_off;
            bio_size(bio) = map->size;
            bio_idx(bio) = 0;
            break;
        }
    }

    // Reset the position in each bvec. Unnecessary with bvec iterators.
    // Will cause multipage bvec capable kernels to lock up.
#ifndef HAVE_BVEC_ITER
    //#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
    for (i = 0; i < bio->bi_vcnt; i++) {
        bio->bi_io_vec[i].bv_len = PAGE_SIZE;
        bio->bi_io_vec[i].bv_offset = 0;
    }
#endif

    // drop our reference to the tp (will queue the orig_bio if nobody else
    // is using it) at this point we set bi_private to the snap_device and
    // change the destructor to use that instead. This only matters on older
    // kernels
    bio->bi_private = dev;
#ifndef HAVE_BIO_BI_POOL
    bio->bi_destructor = bio_destructor_snap_dev;
#endif

    // 将 COW bio 入队由内核线程处理
    bio_queue_add(&dev->sd_cow_bios, bio);
    atomic64_inc(&dev->sd_received_cnt);
    smp_wmb();

    tp_put(tp);

    return;

error:
    LOG_ERROR(ret, "error during bio read complete callback");
    tracer_set_fail_state(dev, ret);
    tp_put(tp);
    bio_free_clone(bio);
}

#ifdef HAVE_BIO_ENDIO_INT

/**
 * on_bio_read_complete() - &struct bio 的 I/O 完成时执行，可赋给 bi_end_io。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @bytes: 未使用。
 * @err: 错误码（errno）。
 *
 * Return: 0 表示整个 bio 的 I/O 已结束，1 表示该 bio 还有剩余字节。
 */
static int on_bio_read_complete(struct bio *bio, unsigned int bytes, int err)
{
    if (bio->bi_size)
        return 1;
    __on_bio_read_complete(bio, err);
    return 0;
}

#elif !defined HAVE_BIO_ENDIO_1

/**
 * on_bio_read_complete() - &struct bio 的 I/O 完成时执行，可赋给 bi_end_io。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @err: 错误码（errno）。
 *
 * Return: 0 表示整个 bio 的 I/O 已结束，1 表示该 bio 还有剩余字节。
 */
static void on_bio_read_complete(struct bio *bio, int err)
{
    if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
        err = -EIO;
    __on_bio_read_complete(bio, err);
}

#elif defined HAVE_BLK_STATUS_T

/**
 * on_bio_read_complete() - &struct bio 的 I/O 完成时执行，可赋给 bi_end_io。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 *
 * Return: 0 表示整个 bio 的 I/O 已结束，1 表示该 bio 还有剩余字节。
 */
static void on_bio_read_complete(struct bio *bio)
{
    __on_bio_read_complete(bio, blk_status_to_errno(bio->bi_status));
}

#else

/**
 * on_bio_read_complete() - &struct bio 的 I/O 完成时执行，可赋给 bi_end_io。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 *
 * Return: 0 表示整个 bio 的 I/O 已结束，1 表示该 bio 还有剩余字节。
 */
static void on_bio_read_complete(struct bio *bio)
{
    __on_bio_read_complete(bio, bio->bi_error);
}
#endif

/**
 * page_get_inode() - 获取承载该页的 inode（若存在）。
 *
 * @pg: &struct page 指针。
 *
 * Return: 存在则返回 &struct inode，否则 NULL。
 */
struct inode *page_get_inode(struct page *pg)
{
    if (!pg) {
        return NULL;
    }

    // 4.8 之前 page_mapping() 未导出，改用 compound_head()
#ifdef HAVE_COMPOUND_HEAD
    //#if LINUX_VERSION_CODE >= KERNEL_VERSION(2.6.22)
    pg = compound_head(pg);
#endif
    if (PageAnon(pg))
        return NULL;
    if (!pg->mapping)
        return NULL;
    if (!virt_addr_valid(pg->mapping))
        return NULL;
    return pg->mapping->host;
}

/**
 * bio_needs_cow() - 判断 &struct bio 是否为写请求或页面对应 inode 与 COW 文件不一致。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 * @inode: 包含 COW 文件的目录的 inode。
 *
 * Return: 0 表示不需要复制，非 0 表示需要复制。
 */
int bio_needs_cow(struct bio *bio, struct inode *inode)
{
    bio_iter_t iter;
    bio_iter_bvec_t bvec;

#if defined HAVE_ENUM_REQ_OPF ||                                                                   \
        (defined HAVE_ENUM_REQ_OP && defined HAVE_ENUM_REQ_OPF_WRITE_ZEROES)
    //#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
    if (bio_op(bio) == REQ_OP_WRITE_ZEROES)
        return 1;
#endif

    // 检查每页 inode，与 COW 文件不一致则返回 true
    bio_for_each_segment (bvec, bio, iter) {
        if (page_get_inode(bio_iter_page(bio, iter)) != inode)
            return 1;
    }

    return 0;
}

#ifndef HAVE_BIO_BI_POOL
/**
 * bio_destructor_tp - bio 释放时调用的析构方法。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 */
static void bio_destructor_tp(struct bio *bio)
{
    struct tracing_params *tp = bio->bi_private;
    bio_free(bio, dev_bioset(tp->dev));
}

/**
 * bio_destructor_snap_dev() - 释放 &struct bio 并将其归还 &struct snap_device 内的 bioset。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 */
static void bio_destructor_snap_dev(struct bio *bio)
{
    struct snap_device *dev = bio->bi_private;
    bio_free(bio, dev_bioset(dev));
}
#endif

#ifndef HAVE_BIO_FREE_PAGES
/**
 * bio_free_pages() - 释放 bio 占用的页。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 */
static void bio_free_pages(struct bio *bio)
{
    struct bio_vec *bvec;
#ifdef HAVE_BVEC_ITER_ALL
    struct bvec_iter_all iter_all;
    bio_for_each_segment_all (bvec, bio, iter_all) {
#else
    int i = 0;
    bio_for_each_segment_all (bvec, bio, i) {
#endif
        struct page *bv_page = bvec->bv_page;
        if (bv_page) {
            __free_page(bv_page);
        }
    }
}
#endif

/**
 * bio_free_clone() - 释放由 bio_make_read_clone() 分配的 bio。
 *
 * @bio: 描述此次 I/O 的 &struct bio。
 *
 * 由克隆 bio 的 endio 完成例程间接调用。
 */
void bio_free_clone(struct bio *bio)
{
    bio_free_pages(bio);
    bio_put(bio);
}

/**
 * bio_make_read_clone() - 创建新的 &struct bio，用于读取现有 bio 中的全部数据。
 *
 * @bs: 分配新 bio 使用的池。
 * @tp: 与输出 bio 一起传递的 &struct tracing_params。
 * @orig_bio: 要从其读取数据的原始 bio。
 * @sect: 输入 bio 内的起始扇区。
 * @pages: 输入 bio 包含的页数。
 * @bio_out: 为读取 orig_bio 中页而创建的 bio。
 * @bytes_added: @bio_out 包含的字节数。
 *
 * 新 bio 可能无法包含原 bio 的全部数据，需多次调用才能读完原 bio。
 *
 * Return: 0 表示成功，非 0 表示失败。
 */
int bio_make_read_clone(struct bio_set *bs, struct tracing_params *tp, struct bio *orig_bio,
                        sector_t sect, unsigned int pages, struct bio **bio_out,
                        unsigned int *bytes_added)
{
    int ret;
    struct bio *new_bio;
    struct page *pg;
    unsigned int i;
    unsigned int bytes;
    unsigned int total = 0;
#ifdef BIO_MAX_PAGES
    unsigned int actual_pages = (pages > BIO_MAX_PAGES) ? BIO_MAX_PAGES : pages;
#else
    unsigned int actual_pages = (pages > BIO_MAX_VECS) ? BIO_MAX_VECS : pages;
#endif

    // 分配 bio 克隆；分配时禁止发起 I/O 以免锁竞争
#ifdef HAVE_BIO_ALLOC_BIOSET_5
    new_bio = bio_alloc_bioset(orig_bio->bi_bdev, actual_pages, REQ_OP_READ, GFP_NOIO, bs);
#else
    new_bio = bio_alloc_bioset(GFP_NOIO, actual_pages, bs);
#endif
    if (!new_bio) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating bio clone - bs = %p, pages = %u", bs, pages);
        goto error;
    }

#ifndef HAVE_BIO_BI_POOL
    new_bio->bi_destructor = bio_destructor_tp;
#endif

    // 填充读 bio
    new_bio->bi_private = tp;
    new_bio->bi_end_io = on_bio_read_complete;
    dattobd_bio_copy_dev(new_bio, orig_bio);
    dattobd_set_bio_ops(new_bio, REQ_OP_READ, 0);
    bio_sector(new_bio) = sect;
    bio_idx(new_bio) = 0;
#ifdef HAVE_BIO_BLKG
    if (orig_bio->bi_blkg) {
        blkg_get(orig_bio->bi_blkg);
        new_bio->bi_blkg = orig_bio->bi_blkg;
    }
#endif
#ifdef HAVE_BIO_REMAPPED
    bio_set_flag(new_bio, BIO_REMAPPED);
#endif

    // 用页填充 bio
    for (i = 0; i < actual_pages; i++) {
        // 分配一页并加入 bio
        pg = alloc_page(GFP_NOIO);
        if (!pg) {
            ret = -ENOMEM;
            LOG_ERROR(ret, "error allocating read bio page %u", i);
            goto error;
        }

        // 将页加入 bio
        bytes = bio_add_page(new_bio, pg, PAGE_SIZE, 0);
        if (bytes != PAGE_SIZE) {
            __free_page(pg);
            break;
        }

        total += bytes;
    }

    *bytes_added = total;
    *bio_out = new_bio;

    // 一切正常时增加引用
    tp_get(tp);
    return 0;

error:
    if (ret)
        LOG_ERROR(ret, "error creating read clone of write bio");
    if (new_bio)
        bio_free_clone(new_bio);

    *bytes_added = 0;
    *bio_out = NULL;
    return ret;
}
