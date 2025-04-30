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

static struct sock *netlink_sock = NULL;

struct mutex netlink_mutex;

/************************NETLINK HANDLER FUNCTIONS************************/

/**
 * __verify_minor() - Verify the supplied minor device number according to the
 *                    requested mode.
 *
 * @minor: the minor number to check.
 * @mode: what to verify:
 * * 0: the minor is not in allocated.
 * * 1: the minor is allocated and is not busy.
 * * 2: the minor is allocated whether busy or not.
 * @snap_devices: the array of snap devices.
 *
 * Return:
 * * 0 - successfully validated.
 * * 1 - a negative errno otherwise.
 */
static int __verify_minor(unsigned int minor, int mode, snap_device_array snap_devices)
{
	// check minor number is within range
	if (minor >= dattobd_max_snap_devices) {
		LOG_ERROR(-EINVAL, "minor number specified is out of range");
		return -EINVAL;
	}

	// check if the device is in use
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

		// check that the device is not busy if we care
		if (mode == 1 && atomic_read(&snap_devices[minor]->sd_refs)) {
			LOG_ERROR(-EBUSY, "device specified is busy");
			return -EBUSY;
		}
	}

	return 0;
}

/**
 * __verify_bdev_writable() - Determines if the block device is writable.
 *
 * @bdev_path: the path to the block device.
 * @out: the result
 *
 * Return:
 * * 0 - successful, @out contains a boolean value indicating whether the bdev
 * is writable.
 * * !0 - errno indicating the error.
 */
static int __verify_bdev_writable(const char *bdev_path, int *out)
{
	int writable = 0;
	struct bdev_wrapper *bdev_w;
	struct super_block *sb;

	// open the base block device
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
 * __netlink_setup() - Sets up for tracking for mounted or unmounted in
 * reload/setup mode as appropriate for the current mount state.
 * block devices
 *
 * @minor: An unallocated device minor number.
 * @bdev_path: The path to the block device.
 * @cow_path: The path to the cow file.
 * @fallocated_space: The specific amount of space to use if non-zero,
 *                    default otherwise.
 * @cache_size: The specific amount of RAM to use for cache, default otherwise.
 * @is_snap: snapshot or incremental.
 * @is_reload: is a reload or a new setup.
 *
 * Return:
 * * 0 - successfully set up.
 * * !0 - errno indicating the error.
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

	// verify that the minor number is valid
	ret = verify_minor_available(minor, snap_devices);
	if (ret) {
		LOG_ERROR(ret, "verify_minor_available");
		goto error;
	}
	// check if block device is mounted
	ret = __verify_bdev_writable(bdev_path, &is_mounted);
	if (ret) {
		LOG_ERROR(ret, "__verify_bdev_writable");
		goto error;
	}
	// check that reload / setup command matches current mount state
	// if (is_mounted && is_reload) {
	// 	ret = -EINVAL;
	// 	LOG_ERROR(ret, "illegal to perform reload while mounted");
	// 	goto error;
	// } else if (!is_mounted && !is_reload) {
	// 	ret = -EINVAL;
	// 	LOG_ERROR(ret, "illegal to perform setup while unmounted");
	// 	goto error;
	// }

	// allocate the tracing struct
	ret = tracer_alloc(&dev);
	if (ret) {
		LOG_ERROR(ret, "tracer_alloc");
		goto error;
	}
	// route to the appropriate setup function
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
 * netlink_destroy() - Tears down an allocated minor device as long as it is not
 *                   referenced(busy).
 *
 * @minor: An allocated device minor number.
 *
 * Return:
 * * 0 - successful.
 * * !0 - errno indicating the error.
 */
static int netlink_destroy(unsigned int minor)
{
	int ret;
	struct snap_device *dev;
	snap_device_array_mut snap_devices = get_snap_device_array_mut();

	LOG_DEBUG("received destroy netlink - %u", minor);

	// verify that the minor number is valid
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
 * netlink_transition_inc() - Transitions the snapshot device to incremental
 *                          tracking.
 *
 * @minor: An allocated device minor number.
 *
 * Return:
 * * 0 - successful.
 * * !0 - errno indicating the error.
 */
static int netlink_transition_inc(unsigned int minor)
{
	int ret;
	struct snap_device *dev;
	snap_device_array_mut snap_devices = get_snap_device_array_mut();

	LOG_DEBUG("received transition inc netlink - %u", minor);

	// verify that the minor number is valid
	ret = verify_minor_in_use_not_busy(minor, snap_devices);
	if (ret)
		goto error;

	dev = snap_devices[minor];

	// check that the device is not in the fail state
	if (tracer_read_fail_state(dev)) {
		ret = -EINVAL;
		LOG_ERROR(ret, "device specified is in the fail state");
		goto error;
	}

	// check that tracer is in active snapshot state
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
 * netlink_transition_snap() - Transitions from active incremental mode to
 *                           snapshot mode.
 *
 * @minor: An allocated device minor number.
 * @cow_path: The path to the cow file.
 * @fallocated_space: The specific amount of space to use if non-zero,
 *                    default otherwise.
 *
 * As a result COW data will be used during snapshotting to preserve snapshot
 * data while the live volume might change.
 *
 * Return:
 * * 0 - successful.
 * * !0 - errno indicating the error.
 */
static int netlink_transition_snap(unsigned int minor, const char *cow_path,
								   unsigned long fallocated_space)
{
	int ret;
	struct snap_device *dev;
	snap_device_array_mut snap_devices = get_snap_device_array_mut();

	LOG_DEBUG("received transition snap netlink - %u : %s", minor, cow_path);

	// verify that the minor number is valid
	ret = verify_minor_in_use_not_busy(minor, snap_devices);
	if (ret)
		goto error;

	dev = snap_devices[minor];

	// check that the device is not in the fail state
	if (tracer_read_fail_state(dev)) {
		ret = -EINVAL;
		LOG_ERROR(ret, "device specified is in the fail state");
		goto error;
	}

	// check that tracer is in active incremental state
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
 * netlink_reconfigure() - Reconfigures the cache size to match the supplied
 *                       value.
 * @minor: An allocated device minor number.
 * @cache_size: The specific amount of RAM to use for cache, default otherwise.
 *
 * Return:
 * * 0 - successful.
 * * !0 - errno indicating the error.
 */
static int netlink_reconfigure(unsigned int minor, unsigned long cache_size)
{
	int ret;
	struct snap_device *dev;
	snap_device_array snap_devices = get_snap_device_array();

	LOG_DEBUG("received reconfigure netlink - %u : %lu", minor, cache_size);

	// verify that the minor number is valid
	ret = verify_minor_in_use_not_busy(minor, snap_devices);
	if (ret)
		goto error;

	dev = snap_devices[minor];

	// check that the device is not in the fail state
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
 * netlink_expand_cow_file() - Expands cow file by the specified size.
 * @size: The size in MiB to expand the cow file by.
 * @minor: An allocated device minor number.
 *
 * Return:
 * * 0 - successful.
 * * !0 - errno indicating the error.
 */
static int netlink_expand_cow_file(uint64_t size, unsigned int minor)
{
	int ret;
	struct snap_device *dev;
	snap_device_array snap_devices = get_snap_device_array();

	LOG_DEBUG("received expand cow file netlink - %u : %llu", minor, size);

	// verify that the minor number is valid
	ret = verify_minor_in_use(minor, snap_devices);
	if (ret)
		goto error;

	dev = snap_devices[minor];

	// check that the device is not in the fail state
	if (tracer_read_fail_state(dev)) {
		ret = -EINVAL;
		LOG_ERROR(ret, "device specified is in the fail state");
		goto error;
	}

	// check that tracer is in active snapshot state
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
 * netlink_reconfigure_auto_expand() - Allows cow file to expand by the specified size during snapshot, specified number of times.
 * @step_size: The step size in MiB to expand the cow file by.
 * @reserved_space: The reserved space in MiB to keep free on the block device.
 * @minor: An allocated device minor number.
 *
 * Return:
 * * 0 - successful.
 * * !0 - errno indicating the error.
 */
static int netlink_reconfigure_auto_expand(uint64_t step_size, uint64_t reserved_space,
										   unsigned int minor)
{
	int ret;
	struct snap_device *dev;
	snap_device_array snap_devices = get_snap_device_array();

	LOG_DEBUG("received reconfigure auto expand netlink - %u : %llu, %llu", minor, step_size,
			  reserved_space);

	// verify that the minor number is valid
	ret = verify_minor_in_use(minor, snap_devices);
	if (ret)
		goto error;

	dev = snap_devices[minor];

	// check that the device is not in the fail state
	if (tracer_read_fail_state(dev)) {
		ret = -EINVAL;
		LOG_ERROR(ret, "device specified is in the fail state");
		goto error;
	}

	// check that tracer is in active snapshot state
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
 * netlink_dattobd_info() - Stores relevant, current &struct snap_device state
 *                        in @info.
 *
 * @info: A @struct dattobd_info object pointer.
 *
 * Return:
 * * 0 - successful.
 * * !0 - errno indicating the error.
 */
static int netlink_dattobd_info(struct dattobd_info *info)
{
	int ret;
	struct snap_device *dev;
	snap_device_array snap_devices = get_snap_device_array();

	LOG_DEBUG("received dattobd info netlink - %u", info->minor);

	// verify that the minor number is valid
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
 * get_free_minor() - Determine the next available device minor number.
 *
 * Return: The next available minor number or an errno indicating the error.
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

		ret = get_netlink_setup_params(req->setup_params, &minor, &bdev_path, &cow_path,
									   &fallocated_space, &cache_size);
		if (ret)
			break;

		ret = netlink_setup_snap(minor, bdev_path, cow_path, fallocated_space, cache_size);
		if (ret)
			break;

		break;

	case MSG_RELOAD_SNAP:

		ret = get_netlink_reload_params(req->reload_params, &minor, &bdev_path, &cow_path,
										&cache_size);
		if (ret)
			break;

		ret = netlink_reload_snap(minor, bdev_path, cow_path, cache_size);
		if (ret)
			break;

		break;
	case MSG_RELOAD_INC:

		ret = get_netlink_reload_params(req->reload_params, &minor, &bdev_path, &cow_path,
										&cache_size);
		if (ret)
			break;

		ret = netlink_reload_inc(minor, bdev_path, cow_path, cache_size);
		if (ret)
			break;

		break;

	case MSG_DESTROY:
		ret = get_netlink_destroy_params(req->destroy_params, &minor);
		if (ret)
			break;

		ret = netlink_destroy(minor);
		if (ret)
			break;

		break;
	case MSG_TRANSITION_INC:
		ret = get_netlink_transition_inc_params(req->transition_inc_params, &minor);
		if (ret)
			break;

		ret = netlink_transition_inc(minor);
		if (ret)
			break;

		break;
	case MSG_TRANSITION_SNAP:

		ret = get_netlink_transition_snap_params(req->transition_snap_params, &minor, &cow_path,
												 &fallocated_space);
		if (ret)
			break;

		ret = netlink_transition_snap(minor, cow_path, fallocated_space);
		if (ret)
			break;

		break;

	case MSG_RECONFIGURE:
		ret = get_netlink_reconfigure_params(req->reconfigure_params, &minor, &cache_size);
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
		ret = get_netlink_expand_cow_file_params(req->expand_cow_file_params, &minor, &cow_size);
		if (ret)
			break;

		ret = netlink_expand_cow_file(cow_size, minor);
		if (ret)
			break;

		break;

	case MSG_RECONFIGURE_AUTO_EXPAND:
		ret = get_netlink_reconfigure_auto_expand_params(req->reconfigure_auto_expand_params,
														 &minor, &step_size, &reserved_space);
		if (ret)
			break;

		ret = netlink_reconfigure_auto_expand(step_size, reserved_space, minor);
		if (ret)
			break;

		break;

	default:
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