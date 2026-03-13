// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "dattobd.h"
#include "includes.h"
#include "logging.h"
#include "userspace_copy_helpers.h"

/**
 * copy_string_from_user() - 从用户空间地址将字符串拷贝到内核空间。
 *
 * @data: 指向字符串的用户空间地址。
 * @out_ptr: 内核分配缓冲区中的字符串，调用方负责释放。
 *
 * 最多从用户空间拷贝 PAGE_SIZE 字节。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int copy_string_from_user(const char __user *data, char **out_ptr)
{
    int ret;
    char *str;

    if (!data) {
        *out_ptr = NULL;
        return 0;
    }

    str = strndup_user(data, PAGE_SIZE);
    if (IS_ERR(str)) {
        ret = PTR_ERR(str);
        goto error;
    }

    *out_ptr = str;
    return 0;

error:
    LOG_ERROR(ret, "error copying string from user space");
    *out_ptr = NULL;
    return ret;
}

/**
 * get_setup_params() - 从用户空间拷贝 &struct setup_params。
 *
 * @in: 用户空间的 &struct setup_params 指针。
 * @minor: 次设备号。
 * @bdev_name: 通过 copy_string_from_user 传入的块设备名。
 * @cow_path: 通过 copy_string_from_user 传入的 COW 文件路径。
 * @fallocated_space: 预分配空间字节数。
 * @cache_size: 区段缓存字节数。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int get_setup_params(const struct setup_params __user *in, unsigned int *minor, char **bdev_name,
                     char **cow_path, unsigned long *fallocated_space, unsigned long *cache_size)
{
    int ret;
    struct setup_params params;

    // 从用户空间拷贝参数结构体
    ret = copy_from_user(&params, in, sizeof(struct setup_params));
    if (ret) {
        ret = -EFAULT;
        LOG_ERROR(ret, "error copying setup_params struct from user space");
        goto error;
    }

    ret = copy_string_from_user((char __user *)params.bdev, bdev_name);
    if (ret)
        goto error;

    if (!*bdev_name) {
        ret = -EINVAL;
        LOG_ERROR(ret, "NULL bdev given");
        goto error;
    }

    ret = copy_string_from_user((char __user *)params.cow, cow_path);
    if (ret)
        goto error;

    if (!*cow_path) {
        ret = -EINVAL;
        LOG_ERROR(ret, "NULL cow given");
        goto error;
    }

    *minor = params.minor;
    *fallocated_space = params.fallocated_space;
    *cache_size = params.cache_size;
    return 0;

error:
    LOG_ERROR(ret, "error copying setup_params from user space");
    if (*bdev_name)
        kfree(*bdev_name);
    if (*cow_path)
        kfree(*cow_path);

    *bdev_name = NULL;
    *cow_path = NULL;
    *minor = 0;
    *fallocated_space = 0;
    *cache_size = 0;
    return ret;
}

/**
 * get_destroy_params() - 从用户空间拷贝 &struct destroy_params。
 *
 * @in: 用户空间的 &struct destroy_params 指针。
 * @minor: 次设备号。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int get_destroy_params(const struct destroy_params __user *in, unsigned int *minor)
{
    int ret;
    struct destroy_params params;

    // 从用户空间拷贝参数结构体
    ret = copy_from_user(&params, in, sizeof(struct destroy_params));
    if (ret) {
        ret = -EFAULT;
        LOG_ERROR(ret, "error copying destroy_params struct from user space");
        goto error;
    }

    *minor = params.minor;
    return 0;

error:
    LOG_ERROR(ret, "error copying destroy_params from user space");
    *minor = 0;
    return ret;
}

/**
 * get_transition_inc_params() - 从用户空间拷贝 &struct transition_inc_params。
 *
 * @in: 用户空间的 &struct transition_inc_params 指针。
 * @minor: 次设备号。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int get_transition_inc_params(const struct transition_inc_params __user *in, unsigned int *minor)
{
    int ret;
    struct transition_inc_params params;

    // 从用户空间拷贝参数结构体
    ret = copy_from_user(&params, in, sizeof(struct transition_inc_params));
    if (ret) {
        ret = -EFAULT;
        LOG_ERROR(ret, "error copying transition_inc_params struct from user space");
        goto error;
    }

    *minor = params.minor;
    return 0;

error:
    LOG_ERROR(ret, "error copying transition_inc_params from user space");
    *minor = 0;
    return ret;
}

/**
 * get_reload_params() - 从用户空间拷贝 &struct reload_params。
 * @in: 用户空间的 &struct reload_params 指针。
 * @minor: 次设备号。
 * @bdev_name: 通过 copy_string_from_user 传入的块设备名。
 * @cow_path: 通过 copy_string_from_user 传入的 COW 文件路径。
 * @cache_size: 区段缓存字节数。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int get_reload_params(const struct reload_params __user *in, unsigned int *minor, char **bdev_name,
                      char **cow_path, unsigned long *cache_size)
{
    int ret;
    struct reload_params params;

    // 从用户空间拷贝参数结构体
    ret = copy_from_user(&params, in, sizeof(struct reload_params));
    if (ret) {
        ret = -EFAULT;
        LOG_ERROR(ret, "error copying reload_params struct from user space");
        goto error;
    }

    ret = copy_string_from_user((char __user *)params.bdev, bdev_name);
    if (ret)
        goto error;

    if (!*bdev_name) {
        ret = -EINVAL;
        LOG_ERROR(ret, "NULL bdev given");
        goto error;
    }

    ret = copy_string_from_user((char __user *)params.cow, cow_path);
    if (ret)
        goto error;

    if (!*cow_path) {
        ret = -EINVAL;
        LOG_ERROR(ret, "NULL cow given");
        goto error;
    }

    *minor = params.minor;
    *cache_size = params.cache_size;
    return 0;

error:
    LOG_ERROR(ret, "error copying reload_params from user space");
    if (*bdev_name)
        kfree(*bdev_name);
    if (*cow_path)
        kfree(*cow_path);

    *bdev_name = NULL;
    *cow_path = NULL;
    *minor = 0;
    *cache_size = 0;
    return ret;
}

/**
 * get_transition_snap_params() - 从用户空间拷贝 &struct transition_snap_params。
 *
 * @in: 用户空间的 &struct transition_snap_params 指针。
 * @minor: 次设备号。
 * @cow_path: 通过 copy_string_from_user 传入的 COW 文件路径。
 * @fallocated_space: 预分配空间字节数。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
int get_transition_snap_params(const struct transition_snap_params __user *in, unsigned int *minor,
                               char **cow_path, unsigned long *fallocated_space)
{
    int ret;
    struct transition_snap_params params;

    // 从用户空间拷贝参数结构体
    ret = copy_from_user(&params, in, sizeof(struct transition_snap_params));
    if (ret) {
        ret = -EFAULT;
        LOG_ERROR(ret, "error copying transition_snap_params struct from user space");
        goto error;
    }

    ret = copy_string_from_user((char __user *)params.cow, cow_path);
    if (ret)
        goto error;

    if (!*cow_path) {
        ret = -EINVAL;
        LOG_ERROR(ret, "NULL cow given");
        goto error;
    }

    *minor = params.minor;
    *fallocated_space = params.fallocated_space;
    return 0;

error:
    LOG_ERROR(ret, "error copying transition_snap_params from user space");
    if (*cow_path)
        kfree(*cow_path);

    *cow_path = NULL;
    *minor = 0;
    *fallocated_space = 0;
    return ret;
}

/**
 * get_reconfigure_params() - 从用户空间拷贝 &struct reconfigure_params。
 * @in: 用户空间的 &struct reconfigure_params 指针。
 * @minor: 次设备号。
 * @cache_size: 区段缓存字节数。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
int get_reconfigure_params(const struct reconfigure_params __user *in, unsigned int *minor,
                           unsigned long *cache_size)
{
    int ret;
    struct reconfigure_params params;

    // 从用户空间拷贝参数结构体
    ret = copy_from_user(&params, in, sizeof(struct reconfigure_params));
    if (ret) {
        ret = -EFAULT;
        LOG_ERROR(ret, "error copying reconfigure_params struct from user space");
        goto error;
    }

    *minor = params.minor;
    *cache_size = params.cache_size;
    return 0;

error:
    LOG_ERROR(ret, "error copying reconfigure_params from user space");

    *minor = 0;
    *cache_size = 0;
    return ret;
}

/**
 * get_expand_cow_file_params() - 从用户空间拷贝 &struct expand_cow_file_params。
 * @in: 用户空间的 &struct expand_cow_file_params 指针。
 * @minor: 次设备号。
 * @size: COW 文件扩展大小（字节）。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
int get_expand_cow_file_params(const struct expand_cow_file_params __user *in, unsigned int *minor,
                               uint64_t *size)
{
    int ret;
    struct expand_cow_file_params params;

    // 从用户空间拷贝参数结构体
    ret = copy_from_user(&params, in, sizeof(struct expand_cow_file_params));
    if (ret) {
        ret = -EFAULT;
        LOG_ERROR(ret, "error copying expand_cow_file_params struct from user space");
        goto error;
    }

    *minor = params.minor;
    *size = params.size;
    return 0;

error:
    LOG_ERROR(ret, "error copying expand_cow_file_params from user space");

    *minor = 0;
    *size = 0;
    return ret;
}

/**
 * get_reconfigure_auto_expand_params() - 从用户空间拷贝 &struct reconfigure_auto_expand_params。
 *
 * @in: 用户空间的 &struct reconfigure_auto_expand_params 指针。
 * @minor: 次设备号。
 * @step_size: 自动扩展步长（字节）。
 * @reserved_space: 保留空间（字节）。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno。
 */
int get_reconfigure_auto_expand_params(const struct reconfigure_auto_expand_params __user *in,
                                       unsigned int *minor, uint64_t *step_size,
                                       uint64_t *reserved_space)
{
    int ret;
    struct reconfigure_auto_expand_params params;

    // 从用户空间拷贝参数结构体
    ret = copy_from_user(&params, in, sizeof(struct reconfigure_auto_expand_params));
    if (ret) {
        ret = -EFAULT;
        LOG_ERROR(ret, "error copying reconfigure_auto_expand_params struct from user space");
        goto error;
    }

    *minor = params.minor;
    *step_size = params.step_size;
    *reserved_space = params.reserved_space;
    return 0;
error:
    LOG_ERROR(ret, "error copying reconfigure_auto_expand_params from user space");

    *minor = 0;
    *step_size = 0;
    *reserved_space = 0;
    return ret;
}

#ifndef HAVE_USER_PATH_AT
int user_path_at(int dfd, const char __user *name, unsigned flags, struct path *path)
{
    struct nameidata nd;
    char *tmp = getname(name);
    int err = PTR_ERR(tmp);
    if (!IS_ERR(tmp)) {
        BUG_ON(flags & LOOKUP_PARENT);
        err = path_lookup(tmp, flags, &nd);
        putname(tmp);
        if (!err) {
            path->dentry = dattobd_get_nd_dentry(nd);
            path->mnt = dattobd_get_nd_mnt(nd);
        }
    }
    return err;
}
#endif
