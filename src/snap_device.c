#include "includes.h"
#include "snap_device.h"
#include "module_control.h"
#include "tracer.h"
#include "logging.h"
#include "tracer_helper.h"

static struct snap_device **snap_devices;
static struct mutex snap_device_lock;

/**
 * init_snap_device_array() - 分配全局设备数组。
 */
int init_snap_device_array(void)
{
    LOG_DEBUG("allocate global device array");
    snap_devices = kzalloc(dattobd_max_snap_devices * sizeof(struct snap_device *), GFP_KERNEL);
    if (!snap_devices) {
        return -ENOMEM;
    }
    mutex_init(&snap_device_lock);
    return 0;
}

/**
 * cleanup_snap_device_array() - 释放全局设备数组。
 */
void cleanup_snap_device_array(void)
{
    LOG_DEBUG("destroying snap devices");
    if (snap_devices) {
        int i;
        struct snap_device *dev;

        snap_device_array_mut snap_devices_wrp = get_snap_device_array_mut();

        tracer_for_each(dev, i)
        {
            if (dev) {
                LOG_DEBUG("destroying minor - %d", i);
                tracer_destroy(dev, snap_devices_wrp);
            }
        }

        put_snap_device_array_mut(snap_devices_wrp);
        kfree(snap_devices);
        snap_devices = NULL;
    }
}

/**
 * get_snap_device_array() - 获取只读的全局设备数组。
 *
 * Return: 只读的全局设备数组。
 */
snap_device_array get_snap_device_array(void)
{
    mutex_lock(&snap_device_lock);
    return snap_devices;
}

/**
 * get_snap_device_array_mut() - 获取可写的全局设备数组。
 *
 * Return: 可写的全局设备数组。
 */
snap_device_array_mut get_snap_device_array_mut(void)
{
    mutex_lock(&snap_device_lock);
    return snap_devices;
}

/**
 * get_snap_device_array_nolock() - 不加锁获取只读的全局设备数组。
 *
 * Return: 全局设备数组。
 */
snap_device_array get_snap_device_array_nolock(void)
{
    return snap_devices;
}

/**
 * put_snap_device_array() - 释放只读全局设备数组的引用。
 *
 * @snap_devices: 只读的全局设备数组。
 */
void put_snap_device_array(snap_device_array snap_devices)
{
    mutex_unlock(&snap_device_lock);
    return;
}

/**
 * put_snap_device_array_mut() - 释放可写全局设备数组的引用。
 *
 * @snap_devices: 可写的全局设备数组。
 */
void put_snap_device_array_mut(snap_device_array_mut snap_devices)
{
    mutex_unlock(&snap_device_lock);
    return;
}

/**
 * put_snap_device_array_nolock() - 释放全局设备数组引用（无锁版本）。
 *
 * @snap_devices: 全局设备数组。
 */
void put_snap_device_array_nolock(snap_device_array snap_devices)
{
    return;
}
