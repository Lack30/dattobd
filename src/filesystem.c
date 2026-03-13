// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "filesystem.h"
#include "includes.h"
#include "logging.h"
#include "userspace_copy_helpers.h"
#include "snap_device.h"
#include "blkdev.h"

// if this isn't defined, we don't need it anyway
#ifndef FMODE_NONOTIFY
#define FMODE_NONOTIFY 0
#endif

#ifndef HAVE_MNT_WANT_WRITE
#define mnt_want_write(x) 0
#define mnt_drop_write (void)sizeof
#endif

#ifndef HAVE_KERN_PATH
//#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
static int kern_path(const char *name, unsigned int flags, struct path *path)
{
    struct nameidata nd;
    int ret = path_lookup(name, flags, &nd);
    if (!ret) {
        path->dentry = dattobd_get_nd_dentry(nd);
        path->mnt = dattobd_get_nd_mnt(nd);
    }
    return ret;
}
#endif

/**
 * dattobd_kernel_read() - 封装 kernel_read，在不支持该接口的系统上提供增强实现。
 * @dfilp: dattobd 可变文件对象。
 * @buf: 至少能容纳 @count 字节的缓冲区。
 * @count: 从 @filp 读取的字节数。
 * @pos: 指向 @filp 中首次顺序访问的偏移；成功返回后为当前文件偏移。
 *
 * Return: 读取的字节数，或负的 errno。
 */
static ssize_t dattobd_kernel_read(struct dattobd_mutable_file *dfilp, struct snap_device *dev,
                                   void *buf, size_t count, loff_t *pos)
{
    ssize_t ret;

    if (dfilp) {
        // no need for making file mutable at read?
        dattobd_mutable_file_unlock(dfilp);
#ifndef HAVE_KERNEL_READ_PPOS
        //#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
        mm_segment_t old_fs;
        old_fs = get_fs();
        set_fs(get_ds());
        ret = vfs_read(dfilp->filp, (char __user *)buf, count, pos);
        set_fs(old_fs);
        return ret;
#else
        ret = kernel_read(dfilp->filp, buf, count, pos);
#endif
        dattobd_mutable_file_lock(dfilp);
        return ret;
    } else {
        LOG_DEBUG("DIO: reading %lu sectors...", count / SECTOR_SIZE);

        ret = file_read_block(dev, buf, *pos, count / SECTOR_SIZE);
        if (!ret)
            ret = count;

        return ret;
    }
}

/**
 * dattobd_kernel_write() - 封装 kernel_write，在不支持该接口的系统上提供增强实现。
 * @dfilp: dattobd 可变文件对象。
 * @buf: 至少包含 @count 字节的缓冲区。
 * @count: 写入 @filp 的字节数。
 * @pos: 指向 @filp 中首次顺序访问的偏移；成功返回后为当前文件偏移。
 *
 * Return: 写入的字节数，或负的 errno。
 */
static ssize_t dattobd_kernel_write(struct dattobd_mutable_file *dfilp, struct snap_device *dev,
                                    const void *buf, size_t count, loff_t *pos)
{
    ssize_t ret;

    if (dfilp) {
        dattobd_mutable_file_unlock(dfilp);
#ifndef HAVE_KERNEL_WRITE_PPOS
        //#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
        mm_segment_t old_fs;

        old_fs = get_fs();
        set_fs(get_ds());
        ret = vfs_write(dfilp->filp, (__force const char __user *)buf, count, pos);
        set_fs(old_fs);
#else
        ret = kernel_write(dfilp->filp, buf, count, pos);
#endif
        dattobd_mutable_file_lock(dfilp);
        return ret;
    } else {
        LOG_DEBUG("DIO: writing %lu sectors...", count / SECTOR_SIZE);

        ret = file_write_block(dev, buf, *pos, count / SECTOR_SIZE);
        if (!ret)
            ret = count;

        return ret;
    }
}

/**
 * file_io() - 对指定文件进行读或写。
 *
 * @dfilp: dattobd 可变文件对象。
 * @dev: 快照设备对象，文件所在设备。
 * @is_write: 整数形式的布尔值，1 表示写，0 表示读。
 * @buf: 写/读的输入或输出缓冲区。
 * @offset: 在 @filp 内首次顺序访问的字节偏移。
 * @len: 传输的字节数。
 * @done: 存放实际传输字节数的指针，不需要时可传 NULL。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
int file_io(struct dattobd_mutable_file *dfilp, struct snap_device *dev, int is_write, void *buf,
            sector_t offset, unsigned long len, unsigned long *done)
{
    ssize_t ret;
    loff_t off = (loff_t)offset;

    if (unlikely(done))
        *done = 0;

    if (is_write)
        ret = dattobd_kernel_write(dfilp, dev, buf, len, &off);
    else
        ret = dattobd_kernel_read(dfilp, dev, buf, len, &off);

    if (unlikely(ret < 0)) {
        LOG_ERROR((int)ret, "error performing file '%s': %llu, %lu", (is_write) ? "write" : "read",
                  (unsigned long long)offset, len);
        return ret;
    }

    if (unlikely(done))
        *done = ret;

    if (unlikely(ret != len)) {
        LOG_ERROR(-EIO, "invalid file '%s' size: %llu, %lu, %lu", (is_write) ? "write" : "read",
                  (unsigned long long)offset, len, (unsigned long)ret);
        ret = -EIO;
    } else {
        ret = 0;
    }

    return ret;
}

inline void file_close(struct dattobd_mutable_file *dfilp)
{
    // force closing dattobd_mutable_file
    if (unlikely(!dfilp))
        return;
    if (atomic_read(&dfilp->writers) > 0) {
        LOG_WARN("closing file that is still unlocked");
    }
    dattobd_mutable_file_unlock(dfilp);
    __file_close_raw(dfilp->filp);
}

inline void __file_close_raw(struct file *filp)
{
    if (unlikely(!filp))
        return;
    mark_inode_dirty(dattobd_get_dentry(filp)->d_inode);
    filp_close(filp, NULL);
}

/**
 * file_open() - 打开文件。
 *
 * @filename: 文件完整路径。
 * @flags: 打开时使用的附加标志。
 * @filp: 成功时得到的目标文件对象指针。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int file_open(const char *filename, int flags, struct file **filp)
{
    int ret;
    struct file *f;

    f = filp_open(filename, flags | O_RDWR | O_LARGEFILE, 0);
    if (!f) {
        ret = -EFAULT;
        LOG_ERROR(ret, "error creating/opening file '%s' (null pointer)", filename);
        goto error;
    } else if (IS_ERR(f)) {
        ret = PTR_ERR(f);
        f = NULL;
        LOG_ERROR(ret, "error creating/opening file '%s' - %d", filename, ret);
        goto error;
    } else if (!S_ISREG(dattobd_get_dentry(f)->d_inode->i_mode)) {
        ret = -EINVAL;
        LOG_ERROR(ret, "'%s' is not a regular file", filename);
        goto error;
    }
    f->f_mode |= FMODE_NONOTIFY;

    *filp = f;
    return 0;

error:
    LOG_ERROR(ret, "error opening file");
    if (f)
        __file_close_raw(f);

    *filp = NULL;
    return ret;
}

#if !defined(HAVE___DENTRY_PATH) && !defined(HAVE_DENTRY_PATH_RAW)
/**
 * dentry_get_relative_pathname() - 返回给定 dentry 相对于其所在块设备挂载点的路径。
 *
 * @dentry: dentry 对象。
 * @buf: 输出路径名，调用方需对返回的缓冲区调用 kfree()。
 * @len_res: 结果路径长度，NULL 表示不关心。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int dentry_get_relative_pathname(struct dentry *dentry, char **buf, int *len_res)
{
    int len = 0;
    char *pathname;
    struct dentry *parent = dentry;

    while (parent->d_parent != parent) {
        len += parent->d_name.len + 1;
        parent = parent->d_parent;
    }

    pathname = kmalloc(len + 1, GFP_KERNEL);
    if (!pathname) {
        LOG_ERROR(-ENOMEM, "error allocating pathname for dentry");
        return -ENOMEM;
    }
    pathname[len] = '\0';
    if (len_res)
        *len_res = len;
    *buf = pathname;

    parent = dentry;
    while (parent->d_parent != parent) {
        len -= parent->d_name.len + 1;
        pathname[len] = '/';
        strncpy(&pathname[len + 1], parent->d_name.name, parent->d_name.len);
        parent = parent->d_parent;
    }

    return 0;
}
#else
/**
 * dentry_get_relative_pathname() - 返回给定 dentry 相对于其所在块设备挂载点的路径。
 *
 * @dentry: dentry 对象。
 * @buf: 输出路径名，调用方需对返回的缓冲区调用 kfree()。
 * @len_res: 结果路径长度，NULL 表示不关心。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int dentry_get_relative_pathname(struct dentry *dentry, char **buf, int *len_res)
{
    int ret, len;
    char *pathname, *page_buf, *final_buf = NULL;

    page_buf = (char *)__get_free_page(GFP_KERNEL);
    if (!page_buf) {
        LOG_ERROR(-ENOMEM, "error allocating page for dentry pathname");
        return -ENOMEM;
    }

#ifdef HAVE___DENTRY_PATH
    spin_lock(&dcache_lock);
    pathname = __dentry_path(dentry, page_buf, PAGE_SIZE);
    spin_unlock(&dcache_lock);
#else
    pathname = dentry_path_raw(dentry, page_buf, PAGE_SIZE);
#endif
    if (IS_ERR(pathname)) {
        ret = PTR_ERR(pathname);
        pathname = NULL;
        LOG_ERROR(ret, "error fetching dentry pathname");
        goto error;
    }

    len = page_buf + PAGE_SIZE - pathname;
    final_buf = kmalloc(len, GFP_KERNEL);
    if (!final_buf) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating pathname for dentry");
        goto error;
    }

    strncpy(final_buf, pathname, len);
    free_page((unsigned long)page_buf);

    *buf = final_buf;
    if (len_res)
        *len_res = len;
    return 0;

error:
    LOG_ERROR(ret, "error converting dentry to relative path name");
    if (final_buf)
        kfree(final_buf);
    if (page_buf)
        free_page((unsigned long)page_buf);

    *buf = NULL;
    if (len_res)
        *len_res = 0;
    return ret;
}
#endif

/**
 * path_get_absolute_pathname() - 从给定的 &struct path 得到绝对路径名。
 *
 * @path: 包含目录及其挂载点的 dentry 的 path。
 * @buf: 输出路径名，调用方需对返回的缓冲区调用 kfree()。
 * @len_res: 结果路径长度，NULL 表示不关心。
 *
 * 绝对路径长度必须小于 PAGE_SIZE 字节。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
static int path_get_absolute_pathname(const struct path *path, char **buf, int *len_res)
{
    int ret, len;
    char *pathname, *page_buf, *final_buf = NULL;

    page_buf = (char *)__get_free_page(GFP_KERNEL);
    if (!page_buf) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating page for absolute pathname");
        goto error;
    }

    pathname = dattobd_d_path(path, page_buf, PAGE_SIZE);
    if (IS_ERR(pathname)) {
        ret = PTR_ERR(pathname);
        pathname = NULL;
        LOG_ERROR(ret, "error fetching absolute pathname");
        goto error;
    }

    len = page_buf + PAGE_SIZE - pathname;
    final_buf = kmalloc(len, GFP_KERNEL);
    if (!final_buf) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating buffer for absolute pathname");
        goto error;
    }

    strncpy(final_buf, pathname, len);
    free_page((unsigned long)page_buf);

    *buf = final_buf;
    if (len_res)
        *len_res = len;
    return 0;

error:
    LOG_ERROR(ret, "error getting absolute pathname from path");
    if (final_buf)
        kfree(final_buf);
    if (page_buf)
        free_page((unsigned long)page_buf);

    *buf = NULL;
    if (len_res)
        *len_res = 0;
    return ret;
}

/**
 * file_get_absolute_pathname() - 从给定的 &struct file 对象得到绝对路径。
 *
 * @dfilp: dattobd 可变文件对象。
 * @buf: 输出路径名，调用方需对返回的缓冲区调用 kfree()。
 * @len_res: 结果路径长度，NULL 表示不关心。
 *
 * 基于 path_get_absolute_pathname() 的封装。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int file_get_absolute_pathname(const struct dattobd_mutable_file *dfilp, char **buf, int *len_res)
{
    struct path path;
    int ret;

    if (unlikely(!dfilp)) {
        ret = -EINVAL;
        goto error;
    }

    path.mnt = dfilp->mnt;
    path.dentry = dfilp->dentry;

    ret = path_get_absolute_pathname(&path, buf, len_res);
    if (ret)
        goto error;

    return 0;

error:
    LOG_ERROR(ret, "error converting file to absolute pathname");
    *buf = NULL;
    *len_res = 0;

    return ret;
}

/**
 * pathname_to_absolute() - 将相对或绝对路径名转换为绝对路径名。
 *
 * @pathname: 待转换的路径名。
 * @buf: 输出路径名，调用方需对返回的缓冲区调用 kfree()。
 * @len_res: 结果路径长度，NULL 表示不关心。
 *
 * 基于 path_get_absolute_pathname() 的封装。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int pathname_to_absolute(const char *pathname, char **buf, int *len_res)
{
    int ret;
    struct path path = {};

    ret = kern_path(pathname, LOOKUP_FOLLOW, &path);
    if (ret) {
        LOG_ERROR(ret, "error finding path for pathname");
        return ret;
    }

    ret = path_get_absolute_pathname(&path, buf, len_res);
    if (ret)
        goto error;

    path_put(&path);
    return 0;

error:
    LOG_ERROR(ret, "error converting pathname to absolute pathname");
    path_put(&path);
    return ret;
}

/**
 * pathname_concat() - 将 @pathname2 拼接到 @pathname1 后。
 *
 * @pathname1: 路径名。
 * @pathname2: 要拼接到 @pathname1 的路径名。
 * @path_out: 输出路径名，调用方需对返回的缓冲区调用 kfree()。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int pathname_concat(const char *pathname1, const char *pathname2, char **path_out)
{
    int pathname1_len, pathname2_len, need_leading_slash = 0;
    int kmalloc_len, offset;
    char *full_pathname;

    pathname1_len = strlen(pathname1);
    pathname2_len = strlen(pathname2);

    if (pathname1[pathname1_len - 1] != '/' && pathname2[0] != '/')
        need_leading_slash = 1;
    else if (pathname1[pathname1_len - 1] == '/' && pathname2[0] == '/')
        pathname1_len--;

    kmalloc_len = pathname1_len + pathname2_len + need_leading_slash + 1;
    full_pathname = kmalloc(kmalloc_len, GFP_KERNEL);
    if (!full_pathname) {
        LOG_ERROR(-ENOMEM, "error allocating buffer for pathname concatenation");
        *path_out = NULL;
        return -ENOMEM;
    }
    full_pathname[pathname1_len + need_leading_slash + pathname2_len] = '\0';

    strncpy(full_pathname, pathname1, pathname1_len);
    if (need_leading_slash)
        full_pathname[pathname1_len] = '/';
    offset = pathname1_len + need_leading_slash;
    strncpy(full_pathname + offset, pathname2, kmalloc_len - offset - 1);

    *path_out = full_pathname;
    return 0;
}

/**
 * user_mount_pathname_concat() - 将相对路径拼接到用户空间传入的挂载路径后。
 *
 * @user_mount_path: 用户空间挂载路径，会被拷贝到内核空间。
 * @rel_path: 内核空间的相对路径。
 * @path_out: 输出路径名，调用方需对返回的缓冲区调用 kfree()。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int user_mount_pathname_concat(const char __user *user_mount_path, const char *rel_path,
                               char **path_out)
{
    int ret;
    char *mount_path;

    ret = copy_string_from_user(user_mount_path, &mount_path);
    if (ret)
        goto error;

    ret = pathname_concat(mount_path, rel_path, path_out);
    if (ret)
        goto error;

    kfree(mount_path);
    return 0;

error:
    LOG_ERROR(ret, "error concatenating mount path to relative path");
    if (mount_path)
        kfree(mount_path);

    *path_out = NULL;
    return ret;
}

/**
 * dattobd_should_remove_suid() - 判断清除 suid 所需的标志。
 *
 * @dentry: &struct dentry 对象指针。
 *
 * Return: 所需的标志。
 */
static int dattobd_should_remove_suid(struct dentry *dentry)
{
    mode_t mode = dentry->d_inode->i_mode;
    int kill = 0;

    // suid always must be killed
    if (unlikely(mode & S_ISUID))
        kill = ATTR_KILL_SUID;

    // sgid without any exec bits is just a mandatory locking mark; leave
    // it alone.  If some exec bits are set, it's a real sgid; kill it.
    if (unlikely((mode & S_ISGID) && (mode & S_IXGRP)))
        kill |= ATTR_KILL_SGID;

    if (unlikely(kill && !capable(CAP_FSETID) && S_ISREG(mode)))
        return kill;

    return 0;
}

/**
 * dattobd_do_truncate() - 修改 &struct file 属性以表示新文件大小；出于安全会同时
 *                         从 @filp 上去除 SUID/SGID 位。
 * @dentry: 描述 @filp 父目录的 &struct dentry。
 * @length: 新长度（字节）。
 * @time_attrs: 时间属性。
 * @filp: &struct file 对象。
 *
 * 因主线内核未导出而在此重实现。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
static int dattobd_do_truncate(struct dentry *dentry, loff_t length, unsigned int time_attrs,
                               struct file *filp)
{
    int ret;
    struct iattr newattrs;

    if (length < 0)
        return -EINVAL;

    newattrs.ia_size = length;
    newattrs.ia_valid = ATTR_SIZE | time_attrs;
    if (filp) {
        newattrs.ia_file = filp;
        newattrs.ia_valid |= ATTR_FILE;
    }

    ret = dattobd_should_remove_suid(dentry);
    if (ret)
        newattrs.ia_valid |= ret | ATTR_FORCE;

    dattobd_inode_lock(dentry->d_inode);
    // replaced with dattobd_mutable_file lock/unlock mechanism
    // inode_attr_unlock(dentry->d_inode);
#ifdef HAVE_NOTIFY_CHANGE_2
    //#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
    ret = notify_change(dentry, &newattrs);
#elif defined HAVE_USER_NAMESPACE_ARGS
    //#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
    ret = notify_change(&init_user_ns, dentry, &newattrs, NULL);
#elif defined HAVE_USER_NAMESPACE_ARGS_2
    ret = notify_change(&nop_mnt_idmap, dentry, &newattrs, NULL);
#else
    ret = notify_change(dentry, &newattrs, NULL);
#endif
    // inode_attr_lock(dentry->d_inode);
    dattobd_inode_unlock(dentry->d_inode);

    return ret;
}

/**
 * file_truncate() - 将文件截断到指定长度。
 *
 * @dfilp: dattobd 可变文件对象。
 * @len: 截断后的长度（字节）。
 *
 * 会对 SUID/SGID 做特殊处理，见 dattobd_do_truncate()。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int file_truncate(struct dattobd_mutable_file *dfilp, loff_t len)
{
    struct inode *inode;
    struct dentry *dentry;
    int ret;

    dentry = dfilp->dentry;
    inode = dfilp->inode;

    dattobd_mutable_file_unlock(dfilp);

#ifdef HAVE_SB_START_WRITE
    //#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
    sb_start_write(inode->i_sb);
#endif

    ret = dattobd_do_truncate(dentry, len, ATTR_MTIME | ATTR_CTIME, dfilp->filp);

#ifdef HAVE_SB_START_WRITE
    //#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
    sb_end_write(inode->i_sb);
#endif

    dattobd_mutable_file_lock(dfilp);

    if (ret) {
        LOG_ERROR(ret, "error performing truncation");
        goto error;
    }

    return 0;

error:
    LOG_ERROR(ret, "error truncating file");
    return ret;
}

/**
 * try_real_fallocate() - 在 @offset 与 @length 指定范围内为文件分配磁盘空间；
 *                        该范围内原先无数据的区域将变为零填充。
 *
 * @dfilp: dattobd 可变文件对象。
 * @offset: 分配起始位置在文件中的偏移。
 * @length: 从 @offset 起要分配的字节数。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
static int try_real_fallocate(struct dattobd_mutable_file *dfilp, uint64_t offset, uint64_t length)
{
    int ret;
    loff_t off = offset;
    loff_t len = length;
    struct inode *inode = dfilp->inode;

    if (off + len > inode->i_sb->s_maxbytes || off + len < 0)
        return -EFBIG;

    dattobd_mutable_file_unlock(dfilp);
#ifdef HAVE_SB_START_WRITE
    sb_start_write(inode->i_sb);
#endif

#if defined(HAVE_VFS_FALLOCATE)
    ret = vfs_fallocate(dfilp->filp, 0, off, len);
#elif defined(HAVE_IOPS_FALLOCATE)
    if (!inode->i_op->fallocate)
        ret = -EOPNOTSUPP;
    else
        ret = inode->i_op->fallocate(inode, 0, offset, len);
#elif defined(HAVE_FOPS_FALLOCATE)
    if (!dfilp->filp->f_op->fallocate)
        ret = -EOPNOTSUPP;
    else
        ret = dfilp->filp->f_op->fallocate(dfilp->filp, 0, off, len);
#else
    ret = -EOPNOTSUPP;
#endif

#ifdef HAVE_SB_START_WRITE
    sb_end_write(inode->i_sb);
#endif
    dattobd_mutable_file_lock(dfilp);

    return ret;
}

/**
 * file_allocate() - 在 @offset 与 @length 指定范围内为文件分配磁盘空间；
 *                   优先使用 try_real_fallocate()，失败则回退为写零。
 *
 * @dfilp: dattobd 可变文件对象。
 * @dev: 文件所在的快照设备对象。
 * @offset: 分配起始位置在文件中的偏移。
 * @length: 从 @offset 起要分配的字节数。
 * @done: 存放实际分配字节数的指针，不需要时可传 NULL。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int file_allocate(struct dattobd_mutable_file *dfilp, struct snap_device *dev, uint64_t offset,
                  uint64_t length, uint64_t *done)
{
    int ret = 0;
    char *page_buf = NULL;
    uint64_t i, write_count;
    char *abs_path = NULL;
    int abs_path_len;
    unsigned long cur_done;

    file_get_absolute_pathname(dfilp, &abs_path, &abs_path_len);

    ret = try_real_fallocate(dfilp, offset, length);

    if (ret && ret != -EOPNOTSUPP)
        goto error;
    else if (!ret) {
        if (done)
            *done = length;
        goto out;
    }

    // fallocate isn't supported, fall back on writing zeros
    if (!abs_path) {
        LOG_WARN("fallocate is not supported for this file system, "
                 "falling back on "
                 "writing zeros");
    } else {
        LOG_WARN("fallocate is not supported for '%s', falling back on "
                 "writing zeros",
                 abs_path);
    }

    // allocate page of zeros
    page_buf = (char *)get_zeroed_page(GFP_KERNEL);
    if (!page_buf) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating zeroed page");
        goto error;
    }

    // may write up to a page too much, ok for our use case
    write_count = NUM_SEGMENTS(length, PAGE_SHIFT);

    if (done)
        *done = 0;

    // if not page aligned, write zeros to that point
    if (offset % PAGE_SIZE != 0) {
        ret = file_write(dfilp, dev, page_buf, offset, PAGE_SIZE - (offset % PAGE_SIZE), &cur_done);
        if (done)
            *done += cur_done;
        if (ret)
            goto error;

        offset += PAGE_SIZE - (offset % PAGE_SIZE);
    }

    // write a page of zeros at a time
    for (i = 0; i < write_count; i++) {
        ret = file_write(dfilp, dev, page_buf, offset + (PAGE_SIZE * i), PAGE_SIZE, &cur_done);
        if (done)
            *done += cur_done;
        if (ret)
            goto error;
    }

    // removed locking as it is managed by the lower level functions

out:
    if (page_buf)
        free_page((unsigned long)page_buf);
    if (abs_path)
        kfree(abs_path);

    return 0;

error:
    if (!abs_path) {
        LOG_ERROR(ret, "error performing fallocate");
    } else {
        LOG_ERROR(ret, "error performing fallocate on file '%s'", abs_path);
    }

    if (page_buf)
        free_page((unsigned long)page_buf);
    if (abs_path)
        kfree(abs_path);

    return ret;
}

/**
 * file_unlink() - 删除一个名称及其所指向的文件（若存在）。
 * @dfilp: dattobd 可变文件对象。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int file_unlink(struct dattobd_mutable_file *dfilp)
{
    int ret = 0;
    struct inode *dir_inode = dfilp->dentry->d_parent->d_inode;
    struct dentry *file_dentry = dfilp->dentry;
    struct vfsmount *mnt = dattobd_get_mnt(dfilp->filp);

    // replaced with dattobd_mutable_file lock/unlock mechanism
    // if(file_dentry->d_inode && inode_attr_is_locked(file_dentry->d_inode)){
    //         inode_attr_unlock(file_dentry->d_inode);
    // }

    if (d_unlinked(file_dentry)) {
        return 0;
    }

    dget(file_dentry);
    igrab(dir_inode);

    ret = mnt_want_write(mnt);
    if (ret) {
        LOG_ERROR(ret, "error getting write access to vfs mount");
        goto mnt_error;
    }

    dattobd_mutable_file_unlock(dfilp);

#ifdef HAVE_VFS_UNLINK_2
    //#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
    ret = vfs_unlink(dir_inode, file_dentry);
#elif defined HAVE_USER_NAMESPACE_ARGS
    //#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
    ret = vfs_unlink(&init_user_ns, dir_inode, file_dentry, NULL);
#elif defined HAVE_USER_NAMESPACE_ARGS_2
    ret = vfs_unlink(file_mnt_idmap(dfilp->filp), dir_inode, file_dentry, NULL);
#else
    ret = vfs_unlink(dir_inode, file_dentry, NULL);
#endif
    if (ret) {
        LOG_ERROR(ret, "error unlinking file");
        goto error;
    }

error:
    mnt_drop_write(mnt);
    dattobd_mutable_file_lock(dfilp);

mnt_error:
    iput(dir_inode);
    dput(file_dentry);

    return ret;
}

#ifndef HAVE_D_UNLINKED
//#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

/**
 * d_unlinked() - 检查目录是否已被 unlink。
 * @dentry: &struct dentry 对象指针。
 *
 * Return: 表示该 dentry 是否已被 unlink 的布尔值。
 */
int d_unlinked(struct dentry *dentry)
{
    return d_unhashed(dentry) && !IS_ROOT(dentry);
}

#endif

#ifndef HAVE_NOOP_LLSEEK
//#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)

/**
 * noop_llseek() - 不执行实际寻址的 llseek 实现。
 * @file: 要寻址的 &struct file 对象
 * @offset: 目标文件偏移
 * @origin: 寻址类型
 *
 * 因非所有内核版本都提供而在此重实现。
 *
 * Return: 当前文件位置。
 */
loff_t noop_llseek(struct file *file, loff_t offset, int origin)
{
    return file->f_pos;
}

#endif

#ifndef HAVE_PATH_PUT
//#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

/**
 * path_put() - 释放对 path 的引用。
 * @path: 要释放引用的 path。
 *
 * 对 path 中的 dentry 和 vfsmount 的引用计数减一。
 */
void path_put(const struct path *path)
{
    dput(path->dentry);
    mntput(path->mnt);
}
#endif

#ifndef HAVE_INODE_LOCK
//#if LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)
/**
 * dattobd_inode_lock() - 锁定 inode 的互斥量。
 * @inode: &struct inode 对象指针。
 *
 * 因非所有内核版本都提供而在此重实现。
 */
void dattobd_inode_lock(struct inode *inode)
{
    mutex_lock(&inode->i_mutex);
}

/**
 * dattobd_inode_unlock() - 解锁 inode 的互斥量。
 * @inode: &struct inode 对象指针。
 *
 * 因非所有内核版本都提供而在此重实现。
 */
void dattobd_inode_unlock(struct inode *inode)
{
    mutex_unlock(&inode->i_mutex);
}
#endif

static struct kmem_cache **vm_area_cache =
        (VM_AREA_CACHEP_ADDR != 0) ?
                (struct kmem_cache **)(VM_AREA_CACHEP_ADDR +
                                       (long long)(((void *)kfree) - (void *)KFREE_ADDR)) :
                NULL;

#ifdef HAVE_VM_AREA_STRUCT_VM_LOCK
static struct kmem_cache **vma_lock_cache =
        (VMA_LOCK_CACHEP_ADDR != 0) ?
                (struct kmem_cache **)(VMA_LOCK_CACHEP_ADDR +
                                       (long long)(((void *)kfree) - (void *)KFREE_ADDR)) :
                NULL;
#endif

struct vm_area_struct *dattobd_vm_area_allocate(struct mm_struct *mm)
{
    struct vm_area_struct *vma;
    static const struct vm_operations_struct dummy_vm_ops = {};

    if (!vm_area_cache) {
        LOG_ERROR(-ENOTSUPP, "vm_area_cachep was not found");
        return NULL;
    }
    vma = kmem_cache_zalloc(*vm_area_cache, GFP_KERNEL);
    if (!vma) {
        LOG_ERROR(-ENOMEM, "kmem_cache_zalloc() failed");
        return NULL;
    }

#ifdef HAVE_VM_AREA_STRUCT_VM_LOCK
    vma->vm_lock = kmem_cache_zalloc(*vma_lock_cache, GFP_KERNEL);
    if (!vma->vm_lock) {
        LOG_ERROR(-ENOMEM, "kmem_cache_zalloc() failed");
        kmem_cache_free(*vm_area_cache, vma);
        return NULL;
    }
    init_rwsem(&vma->vm_lock->lock);
    vma->vm_lock_seq = -1;
#endif

    vma->vm_mm = mm;
    vma->vm_ops = &dummy_vm_ops;
    INIT_LIST_HEAD(&vma->anon_vma_chain);
    return vma;
}

void dattobd_vm_area_free(struct vm_area_struct *vma)
{
    kmem_cache_free(*vm_area_cache, vma);
}

void dattobd_mm_lock(struct mm_struct *mm)
{
#ifdef HAVE_MMAP_WRITE_LOCK
    mmap_write_lock(mm);
#else
    down_write(&mm->mmap_sem);
#endif
}

void dattobd_mm_unlock(struct mm_struct *mm)
{
#ifdef HAVE_MMAP_WRITE_LOCK
    mmap_write_unlock(mm);
#else
    up_write(&mm->mmap_sem);
#endif
}

// removed file_switch_lock as it is managed by the dattobd_mutable_file
// void file_switch_lock(struct file* filp, bool lock, bool mark_dirty)
// {
//         struct inode* inode;

//         if(!filp) return;

//         inode= dattobd_get_dentry(filp)->d_inode;
//         igrab(inode);

//         if(lock){
//                 inode->i_flags |= S_IMMUTABLE;
//         }else{
//                 inode->i_flags &= ~S_IMMUTABLE;
//         }

//         if(mark_dirty){
//                 mark_inode_dirty(inode);
//         }

//         iput(inode);
// }

int file_write_block(struct snap_device *dev, const void *block, size_t offset, size_t len)
{
    int ret;
    int bytes;
    char *data;
    struct page *pg;
    struct bio_set *bs;
    struct bio *new_bio;
    struct block_device *bdev;
    sector_t start_sect;
    int sectors_processed;
    int iterations_done;
    int bytes_written;

    ret = 0;
    bs = dev_bioset(dev);
    bdev = dev->sd_base_dev->bdev;
    sectors_processed = 0;

write_bio:
    start_sect = sector_by_offset(dev, offset);
    if (start_sect == SECTOR_INVALID) {
        LOG_WARN("Possible write IO to the end of file (offset=%lu)", offset);
        ret = -EFAULT;
        goto out;
    }

#ifdef HAVE_BIO_ALLOC
    new_bio = bio_alloc(GFP_NOIO, 1);
#else
    new_bio = bio_alloc(bdev, 1, 0, GFP_KERNEL);
#endif
    if (!new_bio) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating bio (write) - bs = %p", bs);
        goto out;
    }

    dattobd_bio_set_dev(new_bio, bdev);
    dattobd_set_bio_ops(new_bio, REQ_OP_READ, 0);
    //from bio_helper.h
    bio_sector(new_bio) = start_sect;
    bio_idx(new_bio) = 0;

    pg = alloc_page(GFP_NOIO);
    if (!pg) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating read bio page");
        goto out;
    }

    data = kmap(pg);
    iterations_done = 0;
    bytes_written = 0;

    do {
        bytes_written = iterations_done * SECTOR_SIZE;
        memcpy(data + bytes_written, block + sectors_processed * SECTOR_SIZE, SECTOR_SIZE);
        offset += SECTOR_SIZE;
        sectors_processed++;
        iterations_done++;
    } while (sectors_processed < len &&
             sector_by_offset(dev, offset) == start_sect + iterations_done);

    kunmap(pg);

    bytes_written = iterations_done * SECTOR_SIZE;
    bytes = bio_add_page(new_bio, pg, bytes_written, 0);
    if (bytes != bytes_written) {
        LOG_DEBUG("bio_add_page() error!");
        __free_page(pg);
        ret = -EFAULT;
        goto out;
    }

    if (dev->sd_cow_inode)
        pg->mapping = dev->sd_cow_inode->i_mapping;

    ret = dattobd_submit_bio_wait(new_bio);
    if (ret) {
        LOG_ERROR(ret, "submit_bio_wait() error!");
        goto out;
    }

    pg->mapping = NULL;
    bio_free_clone(new_bio);
    new_bio = NULL;

    if (sectors_processed != len)
        goto write_bio;

out:
    if (new_bio) {
        pg->mapping = NULL;
        bio_free_clone(new_bio);
    }

    return ret;
}

int file_read_block(struct snap_device *dev, void *block, size_t offset, size_t len)
{
    int ret;
    int bytes;
    struct page *pg;
    struct bio_set *bs;
    struct bio *new_bio;
    struct block_device *bdev;
    sector_t start_sect;
    struct bio_vec *bvec;
#ifdef HAVE_BVEC_ITER_ALL
    struct bvec_iter_all iter;
#else
    int i = 0;
#endif
    int sectors_processed;
    int iterations_done;
    int bytes_to_read;
    int buf_offset;

    ret = 0;
    bs = dev_bioset(dev);
    bdev = dev->sd_base_dev->bdev;
    sectors_processed = 0;
    WARN_ON(len > SECTORS_PER_BLOCK);

read_bio:
    start_sect = sector_by_offset(dev, offset);
    if (start_sect == SECTOR_INVALID) {
        LOG_WARN("Possible read IO to the end of file (offset=%lu)", offset);
        ret = -EFAULT;
        goto out;
    }
#ifdef HAVE_BIO_ALLOC
    new_bio = bio_alloc(GFP_NOIO, 1);
#else
    new_bio = bio_alloc(bdev, 1, 0, GFP_KERNEL);
#endif
    if (!new_bio) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating bio (read) - bs = %p", bs);
        goto out;
    }
    dattobd_bio_set_dev(new_bio, bdev);
    dattobd_set_bio_ops(new_bio, REQ_OP_READ, 0);
    bio_sector(new_bio) = start_sect;
    bio_idx(new_bio) = 0;

    //allocate a page and add it to our bio
    pg = alloc_page(GFP_NOIO);
    if (!pg) {
        ret = -ENOMEM;
        LOG_ERROR(ret, "error allocating read bio page");
        goto out;
    }

    iterations_done = 0;
    bytes_to_read = 0;
    buf_offset = sectors_processed * SECTOR_SIZE;

    do {
        offset += SECTOR_SIZE;
        sectors_processed++;
        iterations_done++;
    } while (sectors_processed < len &&
             sector_by_offset(dev, offset) == start_sect + iterations_done);

    bytes_to_read = iterations_done * SECTOR_SIZE;
    bytes = bio_add_page(new_bio, pg, bytes_to_read, 0);
    if (bytes != bytes_to_read) {
        LOG_DEBUG("bio_add_page() error!");
        __free_page(pg);
        ret = -EFAULT;
        goto out;
    }

    if (dev->sd_cow_inode)
        pg->mapping = dev->sd_cow_inode->i_mapping;

    ret = dattobd_submit_bio_wait(new_bio);
    if (ret) {
        LOG_ERROR(ret, "submit_bio_wait() error!");
        goto out;
    }

#ifdef HAVE_BVEC_ITER_ALL
    bio_for_each_segment_all (bvec, new_bio, iter) {
#else
    bio_for_each_segment_all (bvec, new_bio, i) {
#endif
        struct page *pg = bvec->bv_page;
        char *data = kmap(pg);
        WARN_ON(bytes_to_read != bvec->bv_len);
        memcpy(block + buf_offset, data, bytes_to_read);
        kunmap(pg);
        // in an impossible case if we have more
        // than one page (should never happen)
        break;
    }

    pg->mapping = NULL;
    bio_free_clone(new_bio);
    new_bio = NULL;

    if (sectors_processed != len)
        goto read_bio;

out:
    if (new_bio) {
        pg->mapping = NULL;
        bio_free_clone(new_bio);
    }

    return ret;
}

sector_t sector_by_offset(struct snap_device *dev, size_t offset)
{
    unsigned int i;
    struct fiemap_extent *extent = dev->sd_cow_extents;
    for (i = 0; i < dev->sd_cow_ext_cnt; i++) {
        if (offset >= extent[i].fe_logical && offset < extent[i].fe_logical + extent[i].fe_length)
            return (extent[i].fe_physical + (offset - extent[i].fe_logical)) >> 9;
    }

    return SECTOR_INVALID;
}

struct dattobd_mutable_file *dattobd_mutable_file_wrap(struct file *filp)
{
    struct dattobd_mutable_file *dfilp = kzalloc(sizeof(struct dattobd_mutable_file), GFP_KERNEL);
    long ret;

    if (unlikely(!dfilp)) {
        LOG_ERROR(-ENOMEM, "error allocating dattobd mutable file");
        return ERR_PTR(-ENOMEM);
    }

    dfilp->filp = filp;
    dfilp->dentry = dattobd_get_dentry(filp);

    if (unlikely(IS_ERR(dfilp->dentry))) {
        LOG_ERROR((int)PTR_ERR(dfilp->dentry), "error getting dentry from file");
        ret = PTR_ERR(dfilp->dentry);
        goto error;
    }

    if (unlikely(!dfilp->dentry)) {
        LOG_ERROR(-ENOENT, "error getting dentry from file, dentry is absent");
        ret = -ENOENT;
        goto error;
    }

    dfilp->inode = dfilp->dentry->d_inode;

    if (unlikely(IS_ERR(dfilp->inode))) {
        LOG_ERROR((int)PTR_ERR(dfilp->inode), "error getting inode from dentry");
        ret = PTR_ERR(dfilp->inode);
        goto error;
    }

    if (unlikely(!dfilp->inode)) {
        LOG_ERROR(-ENOENT, "error getting inode from dentry, inode is absent");
        ret = -ENOENT;
        goto error;
    }

    dfilp->mnt = dattobd_get_mnt(filp);

    if (unlikely(IS_ERR(dfilp->mnt))) {
        LOG_ERROR((int)PTR_ERR(dfilp->mnt), "error getting vfsmount from file");
        ret = PTR_ERR(dfilp->mnt);
        goto error;
    }

    if (unlikely(!dfilp->mnt)) {
        LOG_ERROR(-ENOENT, "error getting vfsmount from file, vfsmount is absent");
        ret = -ENOENT;
        goto error;
    }

    atomic_set(&dfilp->writers, 0);

    igrab(dfilp->inode);
    if ((~dfilp->inode->i_flags) & S_IMMUTABLE) {
        dfilp->inode->i_flags |= S_IMMUTABLE;
    }
    iput(dfilp->inode);

    return dfilp;
error:
    kfree(dfilp);
    return ERR_PTR(ret);
}

void dattobd_mutable_file_unlock(struct dattobd_mutable_file *dfilp)
{
    if (dfilp) {
        igrab(dfilp->inode);
        dfilp->inode->i_flags &= ~S_IMMUTABLE;
        iput(dfilp->inode);
        atomic_inc(&dfilp->writers);
    }
}

void dattobd_mutable_file_lock(struct dattobd_mutable_file *dfilp)
{
    if (dfilp) {
        if (atomic_dec_and_test(&dfilp->writers)) {
            igrab(dfilp->inode);
            dfilp->inode->i_flags |= S_IMMUTABLE;
            iput(dfilp->inode);
        }
    }
}

void dattobd_mutable_file_unwrap(struct dattobd_mutable_file *dfilp)
{
    if (dfilp) {
        kfree(dfilp);
    }
}
