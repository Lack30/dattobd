// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "blkdev.h"
#include "logging.h"
#include <linux/version.h>

#if !defined HAVE_BLKDEV_GET_BY_PATH && !defined HAVE_BLKDEV_GET_BY_PATH_4 &&                      \
        !defined HAVE_BDEV_OPEN_BY_PATH && !defined HAVE_BDEV_FILE_OPEN_BY_PATH

/**
 * dattobd_lookup_bdev() - 根据路径查找 inode，确认是块设备文件并向内核获取对应的 &struct block_device。
 *
 * @pathname: 块设备文件路径。
 * @mode: 打开模式，通常为 FMODE_READ。
 *
 * Return: 成功返回 block_device 指针，失败为 ERR_PTR() 包装的错误。
 */
static struct block_device *dattobd_lookup_bdev(const char *pathname, fmode_t mode)
{
    int r;
    struct block_device *retbd;
    struct nameidata nd;
    struct inode *inode;
    dev_t dev;

    if ((r = path_lookup(pathname, LOOKUP_FOLLOW, &nd)))
        goto fail;

    inode = dattobd_get_nd_dentry(nd)->d_inode;
    if (!inode) {
        r = -ENOENT;
        goto fail;
    }

    if (!S_ISBLK(inode->i_mode)) {
        r = -ENOTBLK;
        goto fail;
    }
    dev = inode->i_rdev;
    retbd = open_by_devnum(dev, mode);

out:
#ifdef HAVE_PATH_PUT
    path_put(&nd.path);
#else
    dput(nd.dentry);
    mntput(nd.mnt);
#endif
    return retbd;
fail:
    retbd = ERR_PTR(r);
    goto out;
}

/**
 * _blkdev_get_by_path() - 根据 @pathname 获取对应的 @block_device，在 dattobd_lookup_bdev 基础上做少量校验。
 *
 * @pathname: 块设备文件路径。
 * @mode: 打开模式，通常为 FMODE_READ。
 * @holder: 未使用。
 *
 * Return: 成功返回 block_device 指针，失败为 ERR_PTR() 包装的错误。
 */
static struct block_device *_blkdev_get_by_path(const char *pathname, fmode_t mode, void *holder)
{
    struct block_device *bdev;
    bdev = dattobd_lookup_bdev(pathname, mode);
    if (IS_ERR(bdev))
        return bdev;

    if ((mode & FMODE_WRITE) && bdev_read_only(bdev)) {
        dattobd_blkdev_put(bdev);
        return ERR_PTR(-EACCES);
    }

    return bdev;
}

#endif

/**
 * dattobd_blkdev_by_path() - 根据 @path 获取块设备；根据内核可用接口选用不同实现，
 *                            返回包含 block_device 与 holder 信息的 bdev_wrapper，兼容 6.8+ 内核。
 *
 * @path: 块设备文件路径。
 * @mode: 打开模式，通常为 FMODE_READ。
 * @holder: 未使用。
 *
 * Return: 成功返回 bdev_wrapper 指针，失败为 ERR_PTR() 包装的错误。
 */
struct bdev_wrapper *dattobd_blkdev_by_path(const char *path, fmode_t mode, void *holder)
{
    struct bdev_wrapper *bw = kmalloc(sizeof(struct bdev_wrapper), GFP_KERNEL);

    if (!bw) {
        return ERR_PTR(-ENOMEM);
    }

#if defined HAVE_BDEV_OPEN_BY_PATH
    bw->_internal.handle = bdev_open_by_path(path, mode, holder, NULL);
    if (IS_ERR(bw->_internal.handle)) {
        void *error = bw->_internal.handle;
        kfree(bw);
        return error;
    }
    bw->bdev = bw->_internal.handle->bdev;
#elif defined HAVE_BLKDEV_GET_BY_PATH_4
    bw->bdev = blkdev_get_by_path(path, mode, holder, NULL);
#elif defined HAVE_BLKDEV_GET_BY_PATH
    bw->bdev = blkdev_get_by_path(path, mode, holder);
#elif defined HAVE_BDEV_FILE_OPEN_BY_PATH
    bw->_internal.file = bdev_file_open_by_path(path, mode, holder, NULL);
    if (IS_ERR(bw->_internal.file)) {
        void *error = bw->_internal.file;
        kfree(bw);
        return error;
    }
    bw->bdev = file_bdev(bw->_internal.file);
#else
    bw->bdev = _blkdev_get_by_path(path, mode, holder);
#endif

    if (IS_ERR_OR_NULL(bw->bdev)) {
        void *error = bw->bdev ? bw->bdev : ERR_PTR(-ENOENT);
        kfree(bw);
        return error;
    }

    return bw;
}

/**
 * dattobd_get_super() - 在超级块链表中查找挂载在 @bd 上的文件系统的超级块；
 *                       根据内核可用接口选用不同实现。
 *
 * @bd: 已挂载的块设备指针。
 *
 * Return: 成功返回 super_block 指针，否则 NULL。
 */
struct super_block *dattobd_get_super(struct block_device *bd)
{
#if defined HAVE_BD_SUPER
    return (bd != NULL) ? bd->bd_super : NULL;
#elif defined HAVE_GET_SUPER
    return get_super(bdev);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    return (struct super_block *)(bd->bd_holder);
#elif GET_ACTIVE_SUPER_ADDR != 0
    struct super_block *(*get_active_superblock)(struct block_device *) =
            (GET_ACTIVE_SUPER_ADDR != 0) ?
                    (struct super_block * (*)(struct block_device *))(
                            GET_ACTIVE_SUPER_ADDR +
                            (long long)(((void *)kfree) - (void *)KFREE_ADDR)) :
                    NULL;
    return get_active_superblock(bd);
#else
#error "Could not determine super block of block device"
#endif
}

/**
 * dattobd_drop_super() - 释放文件系统超级块的引用；根据内核可用接口执行相应释放操作。
 *
 * @sb: 要释放的超级块指针。
 */
void dattobd_drop_super(struct super_block *sb)
{
#if defined HAVE_BD_SUPER
    return;
#elif defined HAVE_GET_SUPER
    return drop_super(sb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    return;
#elif GET_ACTIVE_SUPER_ADDR != 0
    return;
#else
#error "Could not determine super block of block device"
#endif
}

/**
 * dattobd_blkdev_put() - 释放对块设备的引用；根据内核可用接口执行相应释放操作。
 *
 * @bw: 要释放的 bdev_wrapper 指针。
 */
void dattobd_blkdev_put(struct bdev_wrapper *bw)
{
    if (unlikely(IS_ERR_OR_NULL(bw)))
        return;

#ifdef USE_BDEV_AS_FILE
    if (bw->_internal.file)
        bdev_fput(bw->_internal.file);
#elif defined HAVE_BDEV_RELEASE
    if (bw->_internal.handle)
        bdev_release(bw->_internal.handle);
#elif defined HAVE_BLKDEV_PUT_1
    blkdev_put(bw->bdev);
#elif defined HAVE_BLKDEV_PUT_2
    blkdev_put(bw->bdev, NULL);
#else
    blkdev_put(bw->bdev, FMODE_READ);
#endif
    kfree(bw);
}

/**
 * dattobd_get_start_sect_by_gendisk_for_bio() - 根据 gendisk 与分区号获取分区起始扇区。
 *
 * @gd: gendisk 指针。
 * @partno: 分区号。
 * @result: 存放结果的指针。
 *
 * Return: 成功返回 0，否则返回错误码。
 */
int dattobd_get_start_sect_by_gendisk_for_bio(struct gendisk *gd, u8 partno, sector_t *result)
{
#if defined HAVE_BDGET_DISK
    struct block_device *bd = bdget_disk(gd, partno);
    if (!bd)
        return -1;
    *result = get_start_sect(bd);
    return 0;
#elif defined HAVE_DISK_GET_PART
    struct hd_struct *hd = disk_get_part(gd, partno);
    if (!hd)
        return -1;
    *result = hd->start_sect;
    disk_put_part(hd);
    return 0;
#elif defined HAVE_GENDISK_PART
    *result = gd->part[partno]->start_sect;
    return 0;
#elif defined HAVE_BIO_BI_BDEV
    // 不可达
    LOG_ERROR(-1, "Unreachable code.");
    return -1;
#else
#error "Could not determine starting sector of partition by gendisk and partition number"
#endif
}

/**
 * dattobd_get_kstatfs() - 获取块设备上文件系统的统计信息。
 *
 * @bd: 块设备指针。
 * @statfs: 存放统计信息的结构体指针。
 *
 * Return: 成功返回 0，否则返回错误码。
 */
int dattobd_get_kstatfs(struct block_device *bd, struct kstatfs *statfs)
{
    struct super_block *sb;
    int ret;

    ret = 0;
    sb = dattobd_get_super(bd);

    if (sb) {
        if (sb->s_op && sb->s_op->statfs && sb->s_root) {
            ret = sb->s_op->statfs(sb->s_root, statfs);

            if (ret) {
                LOG_ERROR(ret, "dattobd_get_kstatfs: error getting statfs from super block");
                goto done;
            }

            LOG_DEBUG("dattobd_get_kstatfs: free blocks: %llu, block size: %ld, total: %llu\n",
                      statfs->f_bavail, statfs->f_bsize, statfs->f_bavail * statfs->f_bsize);
            goto done;
        } else {
            ret = -EINVAL;

            LOG_ERROR(
                    ret,
                    "dattobd_get_kstatfs: super block does not have statfs operations or root dentry");
            goto done;
        }
    }

done:
    dattobd_drop_super(sb);
    return ret;
}
