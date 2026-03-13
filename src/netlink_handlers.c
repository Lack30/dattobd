#include "netlink_handlers.h"

#include "blkdev.h"
#include "dattobd.h"
#include "hints.h"
#include "includes.h"
#include "linux/mutex.h"
#include "linux/netlink.h"
#include "linux/stddef.h"
#include "linux/string.h"
#include "logging.h"
#include "module_control.h"
#include "snap_device.h"
#include "tracer.h"
#include "tracer_helper.h"
#include "userspace_copy_helpers.h"
#include "cow_manager.h"

#ifdef HAVE_UAPI_MOUNT_H
#include <uapi/linux/mount.h>
#endif

#define verify_minor_available(minor, snap_devices) __verify_minor(minor, 0, snap_devices)
#define verify_minor_in_use_not_busy(minor, snap_devices) __verify_minor(minor, 1, snap_devices)
#define verify_minor_in_use(minor, snap_devices) __verify_minor(minor, 2, snap_devices)

#define netlink_setup_snap(minor, bdev_path, cow_path, fallocated_space, cache_size)               \
    __netlink_setup(minor, bdev_path, cow_path, fallocated_space, cache_size, 1, 0)
#define netlink_reload_snap(minor, bdev_path, cow_path, cache_size)                                \
    __netlink_setup(minor, bdev_path, cow_path, 0, cache_size, 1, 1)
#define netlink_reload_inc(minor, bdev_path, cow_path, cache_size)                                 \
    __netlink_setup(minor, bdev_path, cow_path, 0, cache_size, 0, 1)

struct mutex netlink_mutex;

static struct sock *netlink_sock = NULL;

/************************NETLINK HANDLER FUNCTIONS************************/

/**
 * __verify_minor() - 按请求模式校验给定的次设备号。
 *
 * @minor: 待检查的次设备号。
 * @mode: 校验内容：
 * * 0: 该 minor 未被分配。
 * * 1: 该 minor 已分配且不忙。
 * * 2: 该 minor 已分配（忙或不忙均可）。
 * @snap_devices: 快照设备数组。
 *
 * Return:
 * * 0 - 校验通过。
 * * 负的 errno - 失败。
 */
static int __verify_minor(unsigned int minor, int mode, snap_device_array snap_devices)
{
    // 检查次设备号是否在有效范围内
    if (minor >= dattobd_max_snap_devices) {
        LOG_ERROR(-EINVAL, "minor number specified is out of range");
        return -EINVAL;
    }

    // 检查设备是否已被占用
    if (mode == 0) {
        if (snap_devices[minor]) {
            LOG_ERROR(-EBUSY, "device specified already exists");
            return -EBUSY;
        }
    } else {
        if (!snap_devices[minor]) {
            LOG_ERROR(-ENOENT, "device specified does not exist");
            return -ENOENT;
        }

        // 在需要时检查设备是否正忙
        if (mode == 1 && atomic_read(&snap_devices[minor]->sd_refs)) {
            LOG_ERROR(-EBUSY, "device specified is busy");
            return -EBUSY;
        }
    }

    return 0;
}

/**
 * __verify_bdev_writable() - 判断块设备是否可写。
 *
 * @bdev_path: 块设备路径。
 * @out: 结果（1 可写，0 不可写）。
 *
 * Return:
 * * 0 - 成功，@out 表示块设备是否可写。
 * * !0 - 表示错误的 errno。
 */
static int __verify_bdev_writable(const char *bdev_path, int *out)
{
    int writable = 0;
    struct bdev_wrapper *bdev_w;
    struct super_block *sb;

    // 打开基块设备
    bdev_w = dattobd_blkdev_by_path(bdev_path, FMODE_READ, NULL);

    if (IS_ERR(bdev_w)) {
        *out = 0;
        return PTR_ERR(bdev_w);
    }

    sb = dattobd_get_super(bdev_w->bdev);
    if (!IS_ERR_OR_NULL(sb)) {
        writable = !(sb->s_flags & MS_RDONLY);
        dattobd_drop_super(sb);
    }

    dattobd_blkdev_put(bdev_w);
    *out = writable;
    return 0;
}

/**
 * __netlink_setup() - 根据当前挂载状态，以重载/新建方式为块设备建立跟踪。
 *
 * @minor: 未分配的次设备号。
 * @bdev_path: 块设备路径。
 * @cow_path: COW 文件路径。
 * @fallocated_space: 非零时为预分配空间大小，否则用默认值。
 * @cache_size: 缓存使用的内存大小，0 表示默认。
 * @is_snap: 1 为快照模式，0 为增量模式。
 * @is_reload: 1 为重载，0 为新建。
 *
 * Return:
 * * 0 - 设置成功。
 * * !0 - 表示错误的 errno。
 */
static int __netlink_setup(unsigned int minor, const char *bdev_path, const char *cow_path,
                           unsigned long fallocated_space, unsigned long cache_size, int is_snap,
                           int is_reload)
{
    int ret, is_mounted;
    struct snap_device *dev = NULL;
    snap_device_array_mut snap_devices = get_snap_device_array_mut();

    LOG_DEBUG("received %s %s netlink - %u : %s : %s", (is_reload) ? "reload" : "setup",
              (is_snap) ? "snap" : "inc", minor, bdev_path, cow_path);

    // 校验次设备号有效且可用
    ret = verify_minor_available(minor, snap_devices);
    if (ret) {
        LOG_ERROR(ret, "verify_minor_available");
        goto error;
    }
    // 检查块设备是否已挂载（可写）
    ret = __verify_bdev_writable(bdev_path, &is_mounted);
    if (ret) {
        LOG_ERROR(ret, "__verify_bdev_writable");
        goto error;
    }
    // 重载/新建命令须与当前挂载状态匹配（以下为历史注释）
    // if (is_mounted && is_reload) {
    // 	ret = -EINVAL;
    // 	LOG_ERROR(ret, "illegal to perform reload while mounted");
    // 	goto error;
    // } else if (!is_mounted && !is_reload) {
    // 	ret = -EINVAL;
    // 	LOG_ERROR(ret, "illegal to perform setup while unmounted");
    // 	goto error;
    // }

    // 分配跟踪结构体
    ret = tracer_alloc(&dev);
    if (ret) {
        LOG_ERROR(ret, "tracer_alloc");
        goto error;
    }
    // 根据类型调用对应设置函数
    if (is_snap) {
        // if (is_mounted)
        ret = tracer_setup_active_snap(dev, minor, bdev_path, cow_path, fallocated_space,
                                       cache_size, snap_devices);
        // else
        // ret = tracer_setup_unverified_snap(dev, minor, bdev_path, cow_path, cache_size, snap_devices);
    } else {
        // if (!is_mounted)
        ret = tracer_setup_unverified_inc(dev, minor, bdev_path, cow_path, cache_size,
                                          snap_devices);
        // else {
        // ret = -EINVAL;
        // LOG_ERROR(ret, "illegal to setup as active incremental");
        // goto error;
        // }
    }

    if (ret)
        goto error;

    put_snap_device_array_mut(snap_devices);
    return 0;

error:
    LOG_ERROR(ret, "error during setup netlink handler");
    if (dev)
        kfree(dev);
    put_snap_device_array_mut(snap_devices);
    return ret;
}

/**
 * netlink_destroy() - 在设备未被引用（不忙）时销毁已分配的次设备。
 *
 * @minor: 已分配的次设备号。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
static int netlink_destroy(unsigned int minor)
{
    int ret;
    struct snap_device *dev;
    snap_device_array_mut snap_devices = get_snap_device_array_mut();

    LOG_DEBUG("received destroy netlink - %u", minor);

    // 校验次设备号有效
    ret = verify_minor_in_use_not_busy(minor, snap_devices);
    if (ret) {
        LOG_ERROR(ret, "error during destroy netlink handler");
        put_snap_device_array_mut(snap_devices);
        return ret;
    }

    dev = snap_devices[minor];
    tracer_destroy(dev, snap_devices);
    kfree(dev);

    put_snap_device_array_mut(snap_devices);
    return 0;
}

/**
 * netlink_transition_inc() - 将快照设备切换为增量跟踪模式。
 *
 * @minor: 已分配的次设备号。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
static int netlink_transition_inc(unsigned int minor)
{
    int ret;
    struct snap_device *dev;
    snap_device_array_mut snap_devices = get_snap_device_array_mut();

    LOG_DEBUG("received transition inc netlink - %u", minor);

    // 校验次设备号有效
    ret = verify_minor_in_use_not_busy(minor, snap_devices);
    if (ret)
        goto error;

    dev = snap_devices[minor];

    // 检查设备未处于失败状态
    if (tracer_read_fail_state(dev)) {
        ret = -EINVAL;
        LOG_ERROR(ret, "device specified is in the fail state");
        goto error;
    }

    // 检查 tracer 处于活动快照状态
    if (!test_bit(SNAPSHOT, &dev->sd_state) || !test_bit(ACTIVE, &dev->sd_state)) {
        ret = -EINVAL;
        LOG_ERROR(ret, "device specified is not in active snapshot mode");
        goto error;
    }

    ret = tracer_active_snap_to_inc(dev, snap_devices);
    if (ret)
        goto error;

    put_snap_device_array_mut(snap_devices);
    return 0;

error:
    LOG_ERROR(ret, "error during transition to incremental netlink handler");
    put_snap_device_array_mut(snap_devices);
    return ret;
}

/**
 * netlink_transition_snap() - 从活动增量模式切换回快照模式。
 *
 * @minor: 已分配的次设备号。
 * @cow_path: COW 文件路径。
 * @fallocated_space: 非零时为预分配空间大小，否则用默认值。
 *
 * 切换后快照期间将使用 COW 数据保存快照，而在线卷可能已变化。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
static int netlink_transition_snap(unsigned int minor, const char *cow_path,
                                   unsigned long fallocated_space)
{
    int ret;
    struct snap_device *dev;
    snap_device_array_mut snap_devices = get_snap_device_array_mut();

    LOG_DEBUG("received transition snap netlink - %u : %s", minor, cow_path);

    // 校验次设备号有效
    ret = verify_minor_in_use_not_busy(minor, snap_devices);
    if (ret)
        goto error;

    dev = snap_devices[minor];

    // 检查设备未处于失败状态
    if (tracer_read_fail_state(dev)) {
        ret = -EINVAL;
        LOG_ERROR(ret, "device specified is in the fail state");
        goto error;
    }

    // 检查 tracer 处于活动增量状态
    if (test_bit(SNAPSHOT, &dev->sd_state) || !test_bit(ACTIVE, &dev->sd_state)) {
        ret = -EINVAL;
        LOG_ERROR(ret, "device specified is not in active incremental mode");
        goto error;
    }

    ret = tracer_active_inc_to_snap(dev, cow_path, fallocated_space, snap_devices);
    if (ret)
        goto error;

    put_snap_device_array_mut(snap_devices);
    return 0;

error:
    LOG_ERROR(ret, "error during transition to snapshot netlink handler");
    put_snap_device_array_mut(snap_devices);
    return ret;
}

/**
 * netlink_reconfigure() - 将缓存大小重新配置为指定值。
 * @minor: 已分配的次设备号。
 * @cache_size: 缓存使用的内存大小，0 表示默认。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
static int netlink_reconfigure(unsigned int minor, unsigned long cache_size)
{
    int ret;
    struct snap_device *dev;
    snap_device_array snap_devices = get_snap_device_array();

    LOG_DEBUG("received reconfigure netlink - %u : %lu", minor, cache_size);

    // 校验次设备号有效
    ret = verify_minor_in_use_not_busy(minor, snap_devices);
    if (ret)
        goto error;

    dev = snap_devices[minor];

    // 检查设备未处于失败状态
    if (tracer_read_fail_state(dev)) {
        ret = -EINVAL;
        LOG_ERROR(ret, "device specified is in the fail state");
        goto error;
    }

    tracer_reconfigure(dev, cache_size);

    put_snap_device_array(snap_devices);
    return 0;

error:
    LOG_ERROR(ret, "error during reconfigure netlink handler");
    put_snap_device_array(snap_devices);
    return ret;
}

/**
 * netlink_expand_cow_file() - 按指定大小扩展 COW 文件。
 * @size: 扩展的容量（MiB）。
 * @minor: 已分配的次设备号。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
static int netlink_expand_cow_file(uint64_t size, unsigned int minor)
{
    int ret;
    struct snap_device *dev;
    snap_device_array snap_devices = get_snap_device_array();

    LOG_DEBUG("received expand cow file netlink - %u : %llu", minor, size);

    // 校验次设备号有效
    ret = verify_minor_in_use(minor, snap_devices);
    if (ret)
        goto error;

    dev = snap_devices[minor];

    // 检查设备未处于失败状态
    if (tracer_read_fail_state(dev)) {
        ret = -EINVAL;
        LOG_ERROR(ret, "device specified is in the fail state");
        goto error;
    }

    // 检查 tracer 处于活动快照状态
    if (!test_bit(SNAPSHOT, &dev->sd_state) || !test_bit(ACTIVE, &dev->sd_state) ||
        test_bit(UNVERIFIED, &dev->sd_state)) {
        ret = -EINVAL;
        LOG_ERROR(ret, "device specified is not in active snapshot mode");
        goto error;
    }

    ret = tracer_expand_cow_file_no_check(dev, size * 1024 * 1024);

    if (ret)
        goto error;

    return 0;

error:
    LOG_ERROR(ret, "error during expand cow file netlink handler");
    put_snap_device_array(snap_devices);
    return ret;
}

/**
 * netlink_reconfigure_auto_expand() - 配置快照期间 COW 文件按指定步长自动扩展。
 * @step_size: 每次扩展的步长（MiB）。
 * @reserved_space: 块设备上需保留的空闲空间（MiB）。
 * @minor: 已分配的次设备号。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
static int netlink_reconfigure_auto_expand(uint64_t step_size, uint64_t reserved_space,
                                           unsigned int minor)
{
    int ret;
    struct snap_device *dev;
    snap_device_array snap_devices = get_snap_device_array();

    LOG_DEBUG("received reconfigure auto expand netlink - %u : %llu, %llu", minor, step_size,
              reserved_space);

    // 校验次设备号有效
    ret = verify_minor_in_use(minor, snap_devices);
    if (ret)
        goto error;

    dev = snap_devices[minor];

    // 检查设备未处于失败状态
    if (tracer_read_fail_state(dev)) {
        ret = -EINVAL;
        LOG_ERROR(ret, "device specified is in the fail state");
        goto error;
    }

    // 检查 tracer 处于活动快照状态
    if (!test_bit(SNAPSHOT, &dev->sd_state) || !test_bit(ACTIVE, &dev->sd_state) ||
        test_bit(UNVERIFIED, &dev->sd_state)) {
        ret = -EINVAL;
        LOG_ERROR(ret, "device specified is not in active snapshot mode");
        goto error;
    }

    if (dev->sd_cow->auto_expand == NULL) {
        dev->sd_cow->auto_expand = cow_auto_expand_manager_init();
        if (IS_ERR(dev->sd_cow->auto_expand)) {
            ret = PTR_ERR(dev->sd_cow->auto_expand);
            LOG_ERROR(ret, "error initializing auto expand manager");
            goto error;
        }
    }

    ret = cow_auto_expand_manager_reconfigure(dev->sd_cow->auto_expand, step_size, reserved_space);

    if (ret)
        goto error;

    put_snap_device_array(snap_devices);
    return 0;

error:
    LOG_ERROR(ret, "error during reconfigure auto expand netlink handler");
    put_snap_device_array(snap_devices);
    return ret;
}

/**
 * netlink_dattobd_info() - 将当前 &struct snap_device 的相关状态写入 @info。
 *
 * @info: struct dattobd_info 对象指针。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
static int netlink_dattobd_info(struct dattobd_info *info)
{
    int ret;
    struct snap_device *dev;
    snap_device_array snap_devices = get_snap_device_array();

    LOG_DEBUG("received dattobd info netlink - %u", info->minor);

    // 校验次设备号有效
    ret = verify_minor_in_use(info->minor, snap_devices);
    if (ret)
        goto error;

    dev = snap_devices[info->minor];

    tracer_dattobd_info(dev, info);

    put_snap_device_array(snap_devices);
    return 0;

error:
    LOG_ERROR(ret, "error during reconfigure netlink handler");
    put_snap_device_array(snap_devices);
    return ret;
}

/**
 * get_free_minor() - 获取下一个可用的次设备号。
 *
 * Return: 下一个可用的 minor，或表示错误的负 errno。
 */
static int get_free_minor(void)
{
    struct snap_device *dev;
    int i;
    bool found = false;

    snap_device_array snap_devices = get_snap_device_array();

    tracer_for_each_full(dev, i)
    {
        if (!dev) {
            found = true;
            break;
        }
    }

    put_snap_device_array(snap_devices);

    return (found ? i : -ENOENT);
}

static void handle_request(struct netlink_request *req, struct netlink_response *resp)
{
    int ret, idx;
    char *bdev_path = NULL;
    char *cow_path = NULL;
    struct dattobd_info *info = NULL;
    unsigned int minor = 0;
    unsigned long fallocated_space = 0, cache_size = 0;
    uint64_t cow_size = 0;
    uint64_t step_size = 0, reserved_space = 0;

    mutex_lock(&netlink_mutex);

    switch (req->type) {
    case MSG_PING:
        ret = 0;

        break;
    case MSG_SETUP_SNAP:

        ret = get_setup_params(req->setup_params, &minor, &bdev_path, &cow_path, &fallocated_space,
                               &cache_size);
        if (ret)
            break;

        ret = netlink_setup_snap(minor, bdev_path, cow_path, fallocated_space, cache_size);
        if (ret)
            break;

        break;

    case MSG_RELOAD_SNAP:

        ret = get_reload_params(req->reload_params, &minor, &bdev_path, &cow_path, &cache_size);
        if (ret)
            break;

        ret = netlink_reload_snap(minor, bdev_path, cow_path, cache_size);
        if (ret)
            break;

        break;
    case MSG_RELOAD_INC:

        ret = get_reload_params(req->reload_params, &minor, &bdev_path, &cow_path, &cache_size);
        if (ret)
            break;

        ret = netlink_reload_inc(minor, bdev_path, cow_path, cache_size);
        if (ret)
            break;

        break;

    case MSG_DESTROY:
        ret = get_destroy_params(req->destroy_params, &minor);
        if (ret)
            break;

        ret = netlink_destroy(minor);
        if (ret)
            break;

        break;
    case MSG_TRANSITION_INC:
        ret = get_transition_inc_params(req->transition_inc_params, &minor);
        if (ret)
            break;

        ret = netlink_transition_inc(minor);
        if (ret)
            break;

        break;
    case MSG_TRANSITION_SNAP:

        ret = get_transition_snap_params(req->transition_snap_params, &minor, &cow_path,
                                         &fallocated_space);
        if (ret)
            break;

        ret = netlink_transition_snap(minor, cow_path, fallocated_space);
        if (ret)
            break;

        break;

    case MSG_RECONFIGURE:
        ret = get_reconfigure_params(req->reconfigure_params, &minor, &cache_size);
        if (ret)
            break;

        ret = netlink_reconfigure(minor, cache_size);
        if (ret)
            break;

        break;

    case MSG_DATTOBD_INFO:
        info = kmalloc(sizeof(struct dattobd_info), GFP_KERNEL);
        if (!info) {
            ret = -ENOMEM;
            LOG_ERROR(ret, "error allocating dattobd info");
            break;
        }

        ret = copy_from_user(info, (struct dattobd_info __user *)req->info_params,
                             sizeof(struct dattobd_info));
        if (ret) {
            ret = -EFAULT;
            LOG_ERROR(ret, "error copying dattobd info struct from user space");
            break;
        }

        ret = netlink_dattobd_info(info);
        if (ret)
            break;

        LOG_DEBUG("dattobd info: minor %u, cow_path: %s, bdev: %s, seqid %lld", info->minor,
                  info->cow, info->bdev, info->seqid);
        ret = copy_to_user((struct dattobd_info __user *)req->info_params, info,
                           sizeof(struct dattobd_info));
        if (ret) {
            ret = -EFAULT;
            LOG_ERROR(ret, "error copying dattobd info struct to user space");
            break;
        }

        break;

    case MSG_GET_FREE:
        idx = get_free_minor();
        if (idx < 0) {
            ret = idx;
            LOG_ERROR(ret, "no free devices");
            break;
        }

        resp->get_free.minor = idx;
        break;

    case MSG_EXPAND_COW_FILE:
        ret = get_expand_cow_file_params(req->expand_cow_file_params, &minor, &cow_size);
        if (ret)
            break;

        ret = netlink_expand_cow_file(cow_size, minor);
        if (ret)
            break;

        break;

    case MSG_RECONFIGURE_AUTO_EXPAND:
        ret = get_reconfigure_auto_expand_params(req->reconfigure_auto_expand_params, &minor,
                                                 &step_size, &reserved_space);
        if (ret)
            break;

        ret = netlink_reconfigure_auto_expand(step_size, reserved_space, minor);
        if (ret)
            break;

        break;

    default:
        ret = -EINVAL;
        LOG_ERROR(-EINVAL, "unknown netlink message type");
        break;
    }

    mutex_unlock(&netlink_mutex);

    if (bdev_path)
        kfree(bdev_path);
    if (cow_path)
        kfree(cow_path);
    if (info)
        kfree(info);

    resp->ret = ret;
    resp->type = req->type;
}

int dattobd_netlink_sendto(struct netlink_response *resp, int pid)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;
    size_t payload_size = sizeof(struct netlink_response);

    nl_skb = nlmsg_new(NLMSG_SPACE(payload_size), GFP_ATOMIC);
    if (!nl_skb) {
        return -1;
    }

    nlh = nlmsg_put(nl_skb, 0, 0, NLMSG_DONE, payload_size, 0);
    if (!nlh) {
        nlmsg_free(nl_skb);
        return -1;
    }

    memcpy(nlmsg_data(nlh), resp, payload_size);
    netlink_unicast(netlink_sock, nl_skb, pid, MSG_DONTWAIT);

    return 0;
}

static int nl_bind(struct net *net, int group)
{
    LOG_DEBUG("bind netlink socket at %d", group);
    return 0;
}

static void recv_cb(struct sk_buff *__skb)
{
    int ret;
    struct nlmsghdr *nlh = NULL;
    struct netlink_request *req = NULL;
    struct netlink_response *resp = NULL;

    struct sk_buff *skb = skb_get(__skb);
    if (skb->len >= NLMSG_SPACE(0)) {
        nlh = nlmsg_hdr(skb);
        req = NLMSG_DATA(nlh);
        if (req) {
            resp = kmalloc(sizeof(struct netlink_response), GFP_KERNEL);
            handle_request(req, resp);
            ret = dattobd_netlink_sendto(resp, nlh->nlmsg_pid);
            if (ret != 0)
                LOG_ERROR(ret, "error sending netlink response");
        }
    }

    if (skb)
        kfree_skb(skb);
    if (resp)
        kfree(resp);
}

int setup_netlink_handler(unsigned int unit)
{
    struct netlink_kernel_cfg cfg = {
        .groups = 0,
        .flags = 0,
        .input = recv_cb,
        .bind = nl_bind,
    };

    LOG_DEBUG("create netlink socket at %d", unit);

    netlink_sock = netlink_kernel_create(&init_net, unit, &cfg);
    if (!netlink_sock) {
        LOG_ERROR(-ENOMEM, "error creating netlink socket");
        return -1;
    }

    return 0;
}

void destroy_netlink_handler(void)
{
    LOG_DEBUG("release netlink socket");
    if (netlink_sock) {
        netlink_kernel_release(netlink_sock);
    }
}