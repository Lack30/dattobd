/*
 * 实现 /proc/datto-info 顺序文件输出，将当前快照设备状态组织为可读的 JSON 风格信息。
 */

#include "cow_manager.h"
#include "dattobd.h"
#include "includes.h"
#include "module_control.h"
#include "netlink_handlers.h"
#include "snap_device.h"
#include "tracer_helper.h"
#include "proc_seq_file.h"

static void *dattobd_proc_start(struct seq_file *m, loff_t *pos);
static void *dattobd_proc_next(struct seq_file *m, void *v, loff_t *pos);
static void dattobd_proc_stop(struct seq_file *m, void *v);
static int dattobd_proc_show(struct seq_file *m, void *v);
static int dattobd_proc_open(struct inode *inode, struct file *filp);
static int dattobd_proc_release(struct inode *inode, struct file *file);

#ifndef HAVE_PROC_OPS
//#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
static const struct file_operations dattobd_proc_fops = {
    .owner = THIS_MODULE,
    .open = dattobd_proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = dattobd_proc_release,
};
#else
static const struct proc_ops dattobd_proc_fops = {
    .proc_open = dattobd_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = dattobd_proc_release,
};
#endif

static const struct seq_operations dattobd_seq_proc_ops = {
    .start = dattobd_proc_start,
    .next = dattobd_proc_next,
    .stop = dattobd_proc_stop,
    .show = dattobd_proc_show,
};

#ifndef HAVE_PROC_OPS

/**
 * get_proc_fops() - 获取文件操作结构体指针
 *
 * Return:
 * &struct file_operations 对象指针。
 */
const struct file_operations *get_proc_fops(void)
{
    return &dattobd_proc_fops;
}

#else // HAVE_PROC_OPS

/**
 * get_proc_fops() - 获取文件操作结构体指针
 *
 * Return:
 * &struct proc_ops 对象指针。
 */
const struct proc_ops *get_proc_fops(void)
{
    return &dattobd_proc_fops;
}

#endif // HAVE_PROC_OPS

static snap_device_array current_snap_devices = NULL;

/**
 * dattobd_proc_get_idx() - 将偏移转换为 @snap_devices 数组中的指针。
 * @pos: 在 @snap_devices 数组中的偏移。
 *
 * Return:
 * * NULL - @pos 无效，表示已越过文件末尾。
 * * !NULL - 指向 @snap_devices 数组中元素的 void* 指针。
 */
static void *dattobd_proc_get_idx(loff_t pos)
{
    if (pos > highest_minor)
        return NULL;
    return (void *)&current_snap_devices[pos];
}

/**
 * dattobd_proc_start() - 准备遍历 @snap_devices 数组。
 *
 * @m: seq_file 结构体指针。
 * @pos: 上一轮迭代的偏移。
 *
 * Return:
 * * NULL - @pos 对应不到有效的 @snap_devices 项。
 * * SEQ_START_TOKEN - 从头开始新一轮迭代，需先输出表头。
 * * 其他 - 指向 @snap_devices 在偏移 @pos 处的指针。
 */
static void *dattobd_proc_start(struct seq_file *m, loff_t *pos)
{
    // 根据目前已输出的量，可能会先调用 *_stop()，再以非零 @pos 调用本函数，
    // 期望从上次中断处继续。
    current_snap_devices = get_snap_device_array();
    if (*pos == 0)
        return SEQ_START_TOKEN;
    return dattobd_proc_get_idx(*pos - 1);
}

/**
 * dattobd_proc_next() - 返回下一次要交给 *_show() 的项并推进 @pos。
 *
 * @m: 序列文件结构体。
 * @v: *_start() 或 *_next() 上次返回的值。
 * @pos: 传入值表示 snap_devices 中下一项的位置；返回后 *pos 为 start() 可用于
 *       查找下一个 snap_device 的位置。
 *
 * Return:
 * * NULL - @pos 不是 @snap_devices 中的有效项。
 * * 其他 - 要交给 *_show() 的项指针。
 */
static void *dattobd_proc_next(struct seq_file *m, void *v, loff_t *pos)
{
    void *dev = dattobd_proc_get_idx(*pos);
    ++*pos;
    return dev;
}

/**
 * dattobd_proc_stop() - 遍历 @snap_devices 数组结束时总会调用。
 * @m: 序列文件结构体。
 * @v: *_start() 或 *_next() 上次返回的值。
 *
 * 当 *_start() 或 *_next() 返回 NULL 时表示遍历结束。
 */
static void dattobd_proc_stop(struct seq_file *m, void *v)
{
    put_snap_device_array(current_snap_devices);
    current_snap_devices = NULL;
}

/**
 * dattobd_proc_show() - 输出 @snap_device 的信息，可选地输出表头或表尾。
 * @m: seq_file 结构体。
 * @v: *_start() 或 *_next() 上次调用提供的项。
 *
 * Return:
 * 成功时恒为 0。
 */
static int dattobd_proc_show(struct seq_file *m, void *v)
{
    struct snap_device **dev_ptr = v;
    struct snap_device *dev = NULL;

    // print the header if the "pointer" really an indication to do so
    if (dev_ptr == SEQ_START_TOKEN) {
        seq_printf(m, "{\n");
        seq_printf(m, "\t\"version\": \"%s\",\n", DATTOBD_VERSION);
        seq_printf(m, "\t\"devices\": [\n");
    }

    // if the pointer is actually a device print it
    if (dev_ptr != SEQ_START_TOKEN && *dev_ptr != NULL) {
        int error;
        dev = *dev_ptr;

        if (dev->sd_minor != lowest_minor)
            seq_printf(m, ",\n");
        seq_printf(m, "\t\t{\n");
        seq_printf(m, "\t\t\t\"minor\": %u,\n", dev->sd_minor);
        seq_printf(m, "\t\t\t\"cow_file\": \"%s\",\n", dev->sd_cow_path);
        seq_printf(m, "\t\t\t\"block_device\": \"%s\",\n", dev->sd_bdev_path);
        seq_printf(m, "\t\t\t\"max_cache\": %lu,\n",
                   (dev->sd_cache_size) ? dev->sd_cache_size : dattobd_cow_max_memory_default);

        if (!test_bit(UNVERIFIED, &dev->sd_state)) {
            seq_printf(m, "\t\t\t\"fallocate\": %llu,\n",
                       ((unsigned long long)dev->sd_falloc_size) * 1024 * 1024);

            if (dev->sd_cow) {
                int i;
                seq_printf(m, "\t\t\t\"cow_size_current\": %llu,\n",
                           (unsigned long long)dev->sd_cow->file_size);

                seq_printf(m, "\t\t\t\"seq_id\": %llu,\n", (unsigned long long)dev->sd_cow->seqid);

                seq_printf(m, "\t\t\t\"uuid\": \"");
                for (i = 0; i < COW_UUID_SIZE; i++) {
                    seq_printf(m, "%02x", dev->sd_cow->uuid[i]);
                }
                seq_printf(m, "\",\n");

                if (dev->sd_cow->version > COW_VERSION_0) {
                    seq_printf(m, "\t\t\t\"version\": %llu,\n", dev->sd_cow->version);
                    seq_printf(m,
                               "\t\t\t\"nr_changed_blocks\": "
                               "%llu,\n",
                               dev->sd_cow->nr_changed_blocks);
                }

                if (dev->sd_cow->auto_expand) {
                    seq_printf(m, "\t\t\t\"auto_expand\": {\n");
                    seq_printf(m, "\t\t\t\t\"step_size_mib\": %llu,\n",
                               (unsigned long long)dev->sd_cow->auto_expand->step_size_mib);
                    seq_printf(m, "\t\t\t\t\"reserved_space_mib\": %llu\n",
                               dev->sd_cow->auto_expand->reserved_space_mib);
                    seq_printf(m, "\t\t\t},\n");
                }
            }
        }

        error = tracer_read_fail_state(dev);
        if (error)
            seq_printf(m, "\t\t\t\"error\": %d,\n", error);

        seq_printf(m, "\t\t\t\"state\": %lu\n", dev->sd_state);
        seq_printf(m, "\t\t}");
    }

    // print the footer if there are no devices to print or if this device
    // has the highest minor
    if ((dev_ptr == SEQ_START_TOKEN && lowest_minor > highest_minor) ||
        (dev && dev->sd_minor == highest_minor)) {
        seq_printf(m, "\n\t]\n");
        seq_printf(m, "}\n");
    }

    return 0;
}

static int dattobd_proc_open(struct inode *inode, struct file *filp)
{
    mutex_lock(&netlink_mutex);
    return seq_open(filp, &dattobd_seq_proc_ops);
}

static int dattobd_proc_release(struct inode *inode, struct file *file)
{
    seq_release(inode, file);
    mutex_unlock(&netlink_mutex);
    return 0;
}
