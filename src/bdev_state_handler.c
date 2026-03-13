// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

#include "bdev_state_handler.h"
#include <linux/version.h>
#include "snap_device.h"

/**
 * auto_transition_dormant() - 将活动快照切换为休眠状态。
 *
 * @minor: 设备次设备号。
 * @snap_devices: 快照设备数组。
 */
static void auto_transition_dormant(unsigned int minor, snap_device_array snap_devices)
{
    LOG_DEBUG("ENTER %s minor: %d", __func__, minor);

    mutex_lock(&netlink_mutex);
    __tracer_active_to_dormant(snap_devices[minor]);
    mutex_unlock(&netlink_mutex);

    LOG_DEBUG("EXIT %s", __func__);
}

/**
 * auto_transition_active() - 将设备切换为活动状态（快照或增量均可）。
 *
 * @minor: 设备次设备号。
 * @dir_name: 用户空间传入的挂载目录名。
 * @snap_devices: 快照设备数组。
 */
static void auto_transition_active(unsigned int minor, const char *dir_name,
                                   snap_device_array_mut snap_devices)
{
    struct snap_device *dev = snap_devices[minor];

    LOG_DEBUG("ENTER %s minor: %d", __func__, minor);
    mutex_lock(&netlink_mutex);

    if (test_bit(UNVERIFIED, &dev->sd_state)) {
        if (test_bit(SNAPSHOT, &dev->sd_state))
            __tracer_unverified_snap_to_active(dev, dir_name, snap_devices);
        else
            __tracer_unverified_inc_to_active(dev, dir_name, snap_devices);
    } else
        __tracer_dormant_to_active(dev, dir_name);

    mutex_unlock(&netlink_mutex);

    LOG_DEBUG("EXIT %s", __func__);
}

/**
 * __handle_bdev_mount_nowrite() - 设备卸载时将其切换为休眠状态。
 *
 * @mnt: &struct vfsmount 对象指针。
 * @idx_out: 输出被切换设备的次设备号。
 * @snap_devices: 快照设备数组。
 *
 * Return: 0 表示成功，非 0 为表示错误的 errno。
 */
static int __handle_bdev_mount_nowrite(const struct vfsmount *mnt, unsigned int *idx_out,
                                       snap_device_array snap_devices)
{
    int ret;
    unsigned int i;
    struct snap_device *dev;
    tracer_for_each(dev, i)
    {
        if (!dev)
            continue;

        if (!test_bit(ACTIVE, &dev->sd_state) || tracer_read_fail_state(dev) || !dev->sd_base_dev ||
            dev->sd_base_dev->bdev != mnt->mnt_sb->s_bdev)
            continue;

        if (dev->sd_cow && dev->sd_cow->dfilp && mnt == dev->sd_cow->dfilp->mnt) {
            LOG_DEBUG("block device umount detected for device %d", i);
            auto_transition_dormant(i, snap_devices);

            ret = 0;
            goto out;
        }
    }
    i = 0;
    ret = -ENODEV;
    LOG_DEBUG("block device umount has not been detected for device");
out:
    *idx_out = i;
    return ret;
}

/**
 * __handle_bdev_mount_writable() - 挂载时若存在休眠设备则将其切换为活动状态。
 *
 * @dir_name: 用户空间传入的挂载目录名。
 * @bdev: 存放 COW 数据的 &struct block_device。
 * @idx_out: 输出被切换设备的次设备号。
 * @snap_devices: 快照设备数组。
 *
 * Return: 0 表示成功，非 0 为表示错误的 errno。
 */
static int __handle_bdev_mount_writable(const char *dir_name, const struct block_device *bdev,
                                        unsigned int *idx_out, snap_device_array_mut snap_devices)
{
    int ret;
    unsigned int i;
    struct snap_device *dev;
    struct bdev_wrapper *cur_bdev;

    LOG_DEBUG("ENTER %s", __func__);
    tracer_for_each(dev, i)
    {
        if (!dev)
            continue;

        if (test_bit(ACTIVE, &dev->sd_state) || tracer_read_fail_state(dev)) {
            if (test_bit(ACTIVE, &dev->sd_state)) {
                LOG_DEBUG("dev IS ACTIVE %d", dev->sd_minor);
            }
            continue;
        }

        if (test_bit(UNVERIFIED, &dev->sd_state)) {
            // 获取当前正在检查的未验证 tracer 对应的块设备
            cur_bdev = dattobd_blkdev_by_path(dev->sd_bdev_path, FMODE_READ, NULL);
            if (IS_ERR(cur_bdev)) {
                cur_bdev = NULL;
                continue;
            }

            // 若 tracer 的块设备存在且与正在挂载的设备一致则执行状态转换
            if (cur_bdev->bdev == bdev) {
                LOG_DEBUG("block device mount detected for unverified device %d", i);
                auto_transition_active(i, dir_name, snap_devices);
                dattobd_blkdev_put(cur_bdev);

                ret = 0;
                goto out;
            }

            // 释放块设备引用
            dattobd_blkdev_put(cur_bdev);

        } else if (dev->sd_base_dev && dev->sd_base_dev->bdev == bdev) {
            LOG_DEBUG("block device mount detected for dormant device %d", i);
            auto_transition_active(i, dir_name, snap_devices);

            ret = 0;
            goto out;
        }
    }
    i = 0;
    ret = -ENODEV;

out:
    LOG_DEBUG("EXIT %s", __func__);
    *idx_out = i;
    return ret;
}

/**
 * handle_bdev_mount_event() - 处理挂载事件的通用实现。
 *
 * @dir_name: 用户空间传入的挂载目录名。
 * @follow_flags: 传入系统调用的标志。
 * @idx_out: 输出被切换设备的次设备号。
 * @mount_writable: 挂载是否为可写。
 *
 * Return: 0 表示成功，非 0 为表示错误的 errno。
 */
int handle_bdev_mount_event(const char *dir_name, int follow_flags, unsigned int *idx_out,
                            int mount_writable)
{
    int ret = 0;
    int lookup_flags = 0; // init_umount LOOKUP_MOUNTPOINT;
    struct path path;
    struct block_device *bdev;

    LOG_DEBUG("ENTER %s", __func__);

    if (!(follow_flags & UMOUNT_NOFOLLOW))
        lookup_flags |= LOOKUP_FOLLOW;

#ifdef HAVE_KERN_PATH
    ret = kern_path(dir_name, lookup_flags, &path);
#else
    ret = user_path_at(AT_FDCWD, dir_name, lookup_flags, &path);
#endif
    LOG_DEBUG("dir_name: %s, lookup_flags: %d", dir_name, lookup_flags);
    if (ret) {
        LOG_DEBUG("error finding path: %s", dir_name);
        goto out_nopath;
    }

    LOG_DEBUG("path->dentry: %s, path->mnt->mnt_root: %s", path.dentry->d_name.name,
              path.mnt->mnt_root->d_name.name);

    if (path.dentry != path.mnt->mnt_root) {
        // 指定路径不是挂载点
        ret = -ENODEV;
        LOG_DEBUG("path specified isn't a mount point %s", dir_name);

        goto out;
    }

    bdev = path.mnt->mnt_sb->s_bdev;
    if (!bdev) {
        LOG_DEBUG("path specified isn't mounted on a block device");
        ret = -ENODEV;
        goto out;
    }

    if (!mount_writable) {
        snap_device_array snap_devices = get_snap_device_array();
        ret = __handle_bdev_mount_nowrite(path.mnt, idx_out, snap_devices);
        put_snap_device_array(snap_devices);
    } else {
        snap_device_array_mut snap_devices = get_snap_device_array_mut();
        ret = __handle_bdev_mount_writable(dir_name, bdev, idx_out, snap_devices);
        put_snap_device_array_mut(snap_devices);
    }
    if (ret) {
        // 未找到与增量设备匹配的块设备
        LOG_DEBUG("no block device found that matched an incremental %s", dir_name);
        goto out;
    }

    path_put(&path);
    return ret;
out:
    path_put(&path);
out_nopath:
    *idx_out = 0;
    return ret;
}

/**
 * post_umount_check() - 确认 umount 成功且驱动处于正常状态。
 *
 * @dormant_ret: 切换为休眠时的返回值。
 * @umount_ret: 原始 umount 调用的返回值。
 * @idx: 设备次设备号。
 * @dir_name: 用户空间传入的挂载目录名。
 */
void post_umount_check(int dormant_ret, int umount_ret, unsigned int idx, const char *dir_name)
{
    struct snap_device *dev;
    struct super_block *sb;
    snap_device_array_mut snap_devices = NULL;

    LOG_DEBUG("ENTER %s", __func__);
    // 若未做任何操作或已失败则直接返回
    if (dormant_ret) {
        LOG_DEBUG("EXIT %s, dormant_ret", __func__);
        return;
    }

    snap_devices = get_snap_device_array_mut();

    dev = snap_devices[idx];

    // 若已成功进入休眠但 umount 失败，则重新激活
    if (umount_ret) {
        struct bdev_wrapper *bdev_w;
        bdev_w = dattobd_blkdev_by_path(dev->sd_bdev_path, FMODE_READ, NULL);
        if (IS_ERR_OR_NULL(bdev_w)) {
            LOG_DEBUG("device gone, moving to error state");
            tracer_set_fail_state(dev, -ENODEV);
            put_snap_device_array_mut(snap_devices);
            return;
        }

        dattobd_blkdev_put(bdev_w);

        LOG_DEBUG("umount call failed, reactivating tracer %u", idx);
        auto_transition_active(idx, dir_name, snap_devices);
        put_snap_device_array_mut(snap_devices);
        return;
    }

    put_snap_device_array_mut(snap_devices);

    // 强制 umount 同步完成
    task_work_flush();

    // 若已休眠但块设备仍被某处挂载则进入失败状态
    sb = dattobd_get_super(dev->sd_base_dev->bdev);
    if (sb) {
        if (!(sb->s_flags & MS_RDONLY)) {
            LOG_ERROR(-EIO, "device still mounted after umounting cow file's "
                            "file-system. entering error state");
            tracer_set_fail_state(dev, -EIO);
            dattobd_drop_super(sb);
            return;
        }
        dattobd_drop_super(sb);
    }

    LOG_DEBUG("EXIT %s", __func__);
}
