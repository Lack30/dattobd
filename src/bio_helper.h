// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#ifndef BIO_HELPER_H

#define BIO_HELPER_H

#include "includes.h"
#include "tracing_params.h"

//#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT 9
#endif
#ifndef SECTOR_SIZE
#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif

#define SECTORS_PER_BLOCK (COW_BLOCK_SIZE / SECTOR_SIZE)
#define SECTOR_TO_BLOCK(sect) ((sect) / SECTORS_PER_BLOCK)

#if !defined HAVE_MAKE_REQUEST_FN_IN_QUEUE && defined HAVE_BDOPS_SUBMIT_BIO
/* 5.9+ 内核：make_request_fn 已从 request_queue 移至 block_device_operations 的 submit_bio */
#define USE_BDOPS_SUBMIT_BIO

#ifdef HAVE_NONVOID_SUBMIT_BIO_1
typedef blk_qc_t(make_request_fn)(struct bio *bio);
#else
typedef void(make_request_fn)(struct bio *bio);
#endif
#endif

/* bio 相关宏 */
#define BIO_SET_SIZE 256
#define bio_last_sector(bio) (bio_sector(bio) + (bio_size(bio) / SECTOR_SIZE))

/* 3.14 起内核改变了 bio_for_each_segment 的用法，勿直接访问相关字段以保持兼容 */
#ifndef HAVE_BVEC_ITER
//#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
typedef int bio_iter_t;
typedef struct bio_vec *bio_iter_bvec_t;
#define bio_iter_len(bio, iter) ((bio)->bi_io_vec[(iter)].bv_len)
#define bio_iter_offset(bio, iter) ((bio)->bi_io_vec[(iter)].bv_offset)
#define bio_iter_page(bio, iter) ((bio)->bi_io_vec[(iter)].bv_page)
#define bio_iter_idx(iter) (iter)
#define bio_sector(bio) (bio)->bi_sector
#define bio_size(bio) (bio)->bi_size
#define bio_idx(bio) (bio)->bi_idx
#else
typedef struct bvec_iter bio_iter_t;
typedef struct bio_vec bio_iter_bvec_t;
#define bio_iter_idx(iter) ((iter).bi_idx)
#define bio_sector(bio) (bio)->bi_iter.bi_sector
#define bio_size(bio) (bio)->bi_iter.bi_size
#define bio_idx(bio) (bio)->bi_iter.bi_idx
#endif

#ifndef HAVE_BIOSET_INIT
//#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
#define dev_bioset(dev) ((dev)->sd_bioset)
#else
#define dev_bioset(dev) (&(dev)->sd_bioset)
#endif

struct bio_sector_map {
    struct bio *bio;
    sector_t sect;
    unsigned int size;
    struct bio_sector_map *next;
};

struct request_queue *dattobd_bio_get_queue(struct bio *bio);

void dattobd_bio_set_dev(struct bio *bio, struct block_device *bdev);

void dattobd_bio_copy_dev(struct bio *dst, struct bio *src);

// 不执行 COW 操作
#ifdef HAVE_ENUM_REQ_OP
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) && LINUX_VERSION_CODE <
/* 对应 KERNEL_VERSION(4,10,0) */
/* deb9 4.9 特例：位 30 与 struct bio 的 bi_opf 操作码位域冲突（占高 3 位），
 * 设置该位会改变 bio 表示的操作。设为 28 可放在 bi_opf 的未用标志位。
 */
#define __DATTOBD_PASSTHROUGH 28
#else
/* 4.8 以下版本用未用标志位，4.9 以上内核用未用操作码位 */
#define __DATTOBD_PASSTHROUGH 30
#endif
#define DATTOBD_PASSTHROUGH (1ULL << __DATTOBD_PASSTHROUGH)

#ifndef HAVE_SUBMIT_BIO_1
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)

#ifndef REQ_DISCARD
#define REQ_DISCARD 0
#endif

#if !defined(HAVE_ENUM_REQ_OPF) && !defined(HAVE_ENUM_REQ_OP)
typedef enum req_op {
    REQ_OP_READ,
    REQ_OP_WRITE,
    REQ_OP_DISCARD,     /* 丢弃扇区请求 */
    REQ_OP_SECURE_ERASE, /* 安全擦除扇区请求 */
    REQ_OP_WRITE_SAME,  /* 同一块多次写入 */
    REQ_OP_FLUSH,       /* 缓存刷写请求 */
} req_op_t;
#endif
typedef enum req_op req_op_t;

extern void dattobd_set_bio_ops(struct bio *bio, req_op_t op, unsigned op_flags);

#define bio_is_discard(bio) ((bio)->bi_rw & REQ_DISCARD)
#define dattobd_submit_bio(bio) submit_bio(0, bio)
#define dattobd_submit_bio_wait(bio) submit_bio_wait(0, bio)

int dattobd_bio_op_flagged(struct bio *bio, unsigned int flag);
void dattobd_bio_op_set_flag(struct bio *bio, unsigned int flag);
void dattobd_bio_op_clear_flag(struct bio *bio, unsigned int flag);

#else

#ifndef HAVE_ENUM_REQ_OPF
//#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
typedef enum req_op req_op_t;
#else
typedef enum req_opf req_op_t;
#endif

void dattobd_set_bio_ops(struct bio *bio, req_op_t op, unsigned op_flags);
int dattobd_bio_op_flagged(struct bio *bio, unsigned int flag);
void dattobd_bio_op_set_flag(struct bio *bio, unsigned int flag);
void dattobd_bio_op_clear_flag(struct bio *bio, unsigned int flag);

#ifdef REQ_DISCARD
#define bio_is_discard(bio) ((bio)->bi_opf & REQ_DISCARD)
#else
#define bio_is_discard(bio) (bio_op(bio) == REQ_OP_DISCARD || bio_op(bio) == REQ_OP_SECURE_ERASE)
#endif

#define dattobd_submit_bio(bio) submit_bio(bio)
#define dattobd_submit_bio_wait(bio) submit_bio_wait(bio)

#endif

struct inode *page_get_inode(struct page *pg);

int bio_needs_cow(struct bio *bio, struct inode *inode);

void bio_free_clone(struct bio *bio);

int bio_make_read_clone(struct bio_set *bs, struct tracing_params *tp, struct bio *orig_bio,
                        sector_t sect, unsigned int pages, struct bio **bio_out,
                        unsigned int *bytes_added);

#ifdef HAVE_BIO_ENDIO_INT
void dattobd_bio_endio(struct bio *bio, int err);
#elif !defined HAVE_BIO_ENDIO_1
void dattobd_bio_endio(struct bio *bio, int err);
#elif defined HAVE_BLK_STATUS_T
void dattobd_bio_endio(struct bio *bio, int err);
#else
void dattobd_bio_endio(struct bio *bio, int err);
#endif

#ifdef HAVE_BIO_BI_BDEV_BD_DISK
#define dattobd_bio_bi_disk(bio) ((bio)->bi_bdev->bd_disk)
#else
#define dattobd_bio_bi_disk(bio) ((bio)->bi_disk)
#endif

#if !defined HAVE_BIO_FOR_EACH_SEGMENT_ALL_1 && !defined HAVE_BIO_FOR_EACH_SEGMENT_ALL_2
#define bio_for_each_segment_all(bvl, bio, i)                                                      \
    for (i = 0, bvl = (bio)->bi_io_vec; i < (bio)->bi_vcnt; i++, bvl++)
#endif

#ifdef USE_BDOPS_SUBMIT_BIO
int tracer_alloc_ops(struct snap_device *dev);
#endif

#endif /* BIO_HELPER_H */
