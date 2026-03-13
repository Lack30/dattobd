// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

/*
 * 实现 block change stream 字符设备的 open/read/poll/release 接口。
 */

#include "block_change_stream_chrdev.h"

#include "block_change_stream.h"
#include "logging.h"
#include "module_control.h"
#include "snap_device.h"

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/poll.h>

static dev_t bcs_chrdev;
static struct cdev bcs_cdev;
static struct class *bcs_class;

static struct snap_device *bcs_get_device(unsigned int minor)
{
    struct snap_device *dev;
    snap_device_array snap_devices = get_snap_device_array();

    if (minor >= dattobd_max_snap_devices) {
        put_snap_device_array(snap_devices);
        return NULL;
    }

    dev = snap_devices[minor];
    put_snap_device_array(snap_devices);

    return dev;
}

static int bcs_chrdev_open(struct inode *inode, struct file *file)
{
    unsigned int minor = iminor(inode);
    struct snap_device *dev = bcs_get_device(minor);
    int ret;

    if (!dev || !dev->sd_bcs)
        return -ENODEV;

    ret = block_change_stream_open(dev);
    if (ret)
        return ret;

    file->private_data = (void *)(unsigned long)minor;
    return 0;
}

static ssize_t bcs_chrdev_read(struct file *file, char __user *buf, size_t length, loff_t *ppos)
{
    unsigned int minor = (unsigned long)file->private_data;
    struct snap_device *dev = bcs_get_device(minor);

    (void)ppos;

    if (!dev || !dev->sd_bcs)
        return -ENODEV;

    return block_change_stream_read(dev, buf, length, file->f_flags & O_NONBLOCK);
}

static __poll_t bcs_chrdev_poll(struct file *file, poll_table *wait)
{
    unsigned int minor = (unsigned long)file->private_data;
    struct snap_device *dev = bcs_get_device(minor);

    if (!dev || !dev->sd_bcs)
        return POLLERR;

    return block_change_stream_poll(dev, file, wait);
}

static int bcs_chrdev_release(struct inode *inode, struct file *file)
{
    unsigned int minor = (unsigned long)file->private_data;
    struct snap_device *dev = bcs_get_device(minor);

    (void)inode;

    if (dev)
        block_change_stream_release(dev);
    file->private_data = NULL;
    return 0;
}

static const struct file_operations bcs_chrdev_fops = {
    .owner = THIS_MODULE,
    .open = bcs_chrdev_open,
    .read = bcs_chrdev_read,
    .poll = bcs_chrdev_poll,
    .release = bcs_chrdev_release,
    .llseek = no_llseek,
};

int register_block_change_stream_chrdev(void)
{
    int ret;
    unsigned int minor;
    char name[32];

    ret = alloc_chrdev_region(&bcs_chrdev, 0, dattobd_max_snap_devices, "dattobcs");
    if (ret) {
        LOG_ERROR(ret, "error allocating block change stream chrdev region");
        return ret;
    }

    cdev_init(&bcs_cdev, &bcs_chrdev_fops);
    bcs_cdev.owner = THIS_MODULE;

    ret = cdev_add(&bcs_cdev, bcs_chrdev, dattobd_max_snap_devices);
    if (ret) {
        LOG_ERROR(ret, "error adding block change stream chrdev");
        goto err_unregister_region;
    }

    bcs_class = class_create(THIS_MODULE, "dattobcs");
    if (IS_ERR(bcs_class)) {
        ret = PTR_ERR(bcs_class);
        bcs_class = NULL;
        LOG_ERROR(ret, "error creating block change stream class");
        goto err_cdev_del;
    }

    for (minor = 0; minor < dattobd_max_snap_devices; minor++) {
        snprintf(name, sizeof(name), BCS_DEVICE_NAME, minor);
        if (IS_ERR(device_create(bcs_class, NULL, MKDEV(MAJOR(bcs_chrdev), minor), NULL, "%s",
                                 name))) {
            ret = -EINVAL;
            LOG_ERROR(ret, "error creating block change stream device node for minor %u", minor);
            goto err_destroy_devices;
        }
    }

    return 0;

err_destroy_devices:
    while (minor > 0) {
        minor--;
        device_destroy(bcs_class, MKDEV(MAJOR(bcs_chrdev), minor));
    }
    class_destroy(bcs_class);
    bcs_class = NULL;
err_cdev_del:
    cdev_del(&bcs_cdev);
err_unregister_region:
    unregister_chrdev_region(bcs_chrdev, dattobd_max_snap_devices);
    return ret;
}

void unregister_block_change_stream_chrdev(void)
{
    unsigned int minor;

    if (bcs_class) {
        for (minor = 0; minor < dattobd_max_snap_devices; minor++)
            device_destroy(bcs_class, MKDEV(MAJOR(bcs_chrdev), minor));
        class_destroy(bcs_class);
        bcs_class = NULL;
    }

    if (bcs_chrdev) {
        cdev_del(&bcs_cdev);
        unregister_chrdev_region(bcs_chrdev, dattobd_max_snap_devices);
        bcs_chrdev = 0;
    }
}
