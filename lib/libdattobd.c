// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Copyright (C) 2015 Datto Inc.
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "dattobd.h"
#include "libdattobd.h"

int datto_netlink_submit(struct netlink_request *req, struct netlink_response *resp)
{
	int sockfd, ret;
	struct sockaddr_nl local, remote;
	struct nlmsghdr *nlh = NULL;
	struct msghdr msg;
	struct iovec iov;
	size_t req_size = sizeof(struct netlink_request);

	sockfd = socket(AF_NETLINK, SOCK_RAW, 25);
	if (sockfd == -1) {
		return -EINVAL;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();

	local.nl_groups = 0;
	if (bind(sockfd, (struct sockaddr *)&local, sizeof(local)) != 0) {
		ret = -EINVAL;
		goto error;
	}

	memset(&remote, 0, sizeof(remote));
	remote.nl_family = AF_NETLINK;
	remote.nl_pid = 0;
	remote.nl_groups = 0;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_pid = local.nl_pid;

	memcpy(NLMSG_DATA(nlh), req, req_size);
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&remote;
	msg.msg_namelen = sizeof(remote);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(sockfd, &msg, 0);
	if (ret < 0) {
		ret = -EINVAL;
		goto error;
	}

	memset(nlh, 0, sizeof(struct nlmsghdr));
	nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct netlink_response));
	ret = recvmsg(sockfd, &msg, 0);
	if (ret < 0) {
		ret = -EINVAL;
		goto error;
	}
	resp = (struct netlink_response *)NLMSG_DATA(nlh);
	ret = resp->ret;

error:
	if (sockfd)
		close(sockfd);

	if (nlh)
		free((void *)nlh);

	return ret;
}

int dattobd_ping(void) {
	int ret;
	struct netlink_request req;
	struct netlink_response resp;

	req.type = MSG_PING;

	ret = datto_netlink_submit(&req, &resp);
	return ret;
}

int dattobd_setup_snapshot(unsigned int minor, char *bdev, char *cow,
						   unsigned long fallocated_space, unsigned long cache_size)
{
	int ret;
	struct netlink_setup_params sp;
	struct netlink_request req;
	struct netlink_response resp;

	sp.minor = minor;
	sp.bdev = bdev;
	sp.cow = cow;
	sp.fallocated_space = fallocated_space;
	sp.cache_size = cache_size;

	req.type = MSG_SETUP_SNAP;
	req.setup_params = &sp;

	ret = datto_netlink_submit(&req, &resp);

	return ret;
}

int dattobd_reload_snapshot(unsigned int minor, char *bdev, char *cow, unsigned long cache_size)
{
	int ret;
	struct netlink_reload_params rp;
	struct netlink_request req;
	struct netlink_response resp;

	rp.minor = minor;
	rp.bdev = bdev;
	rp.cow = cow;
	rp.cache_size = cache_size;

	req.type = MSG_RELOAD_SNAP;
	req.reload_params = &rp;

	ret = datto_netlink_submit(&req, &resp);

	return ret;
}

int dattobd_reload_incremental(unsigned int minor, char *bdev, char *cow, unsigned long cache_size)
{
	int ret;
	struct netlink_reload_params rp;
	struct netlink_request req;
	struct netlink_response resp;

	rp.minor = minor;
	rp.bdev = bdev;
	rp.cow = cow;
	rp.cache_size = cache_size;

	req.type = MSG_RELOAD_INC;
	req.reload_params = &rp;

	ret = datto_netlink_submit(&req, &resp);
	return ret;
}

int dattobd_destroy(unsigned int minor)
{
	int ret;
	struct netlink_destroy_params dp = {
		.minor = minor,
	};
	struct netlink_request req;
	struct netlink_response resp;

	req.type = MSG_DESTROY;
	req.destroy_params = &dp;

	ret = datto_netlink_submit(&req, &resp);

	return ret;
}

int dattobd_transition_incremental(unsigned int minor)
{
	int ret;
	struct netlink_transition_inc_params tip = {
		.minor = minor,
	};
	struct netlink_request req;
	struct netlink_response resp;

	req.type = MSG_TRANSITION_INC;
	req.transition_inc_params = &tip;

	ret = datto_netlink_submit(&req, &resp);

	return ret;
}

int dattobd_transition_snapshot(unsigned int minor, char *cow, unsigned long fallocated_space)
{
	int ret;
	struct netlink_transition_snap_params tp;
	struct netlink_request req;
	struct netlink_response resp;

	tp.minor = minor;
	tp.cow = cow;
	tp.fallocated_space = fallocated_space;

	req.type = MSG_TRANSITION_SNAP;
	req.transition_snap_params = &tp;

	ret = datto_netlink_submit(&req, &resp);
	return ret;
}

int dattobd_reconfigure(unsigned int minor, unsigned long cache_size)
{
	int ret;
	struct netlink_reconfigure_params rp;
	struct netlink_request req;
	struct netlink_response resp;

	rp.minor = minor;
	rp.cache_size = cache_size;

	req.type = MSG_RECONFIGURE;
	req.reconfigure_params = &rp;

	ret = datto_netlink_submit(&req, &resp);
	return ret;
}

int dattobd_info(unsigned int minor, struct dattobd_info *info)
{
	int ret;
	struct netlink_request req;
	struct netlink_response resp;

	if (!info) {
		errno = EINVAL;
		return -1;
	}

	memset(info, 0, sizeof(struct dattobd_info));
	info->minor = minor;

	req.type = MSG_DATTOBD_INFO;
	req.info_params = info;

	ret = datto_netlink_submit(&req, &resp);
	// printf("ok\n");

	return ret;
}

int dattobd_get_free_minor(void)
{
	int ret;
	struct netlink_request req;
	struct netlink_response resp;

	req.type = MSG_GET_FREE;

	ret = datto_netlink_submit(&req, &resp);

	if (!ret)
		return resp.get_free.minor;
	return ret;
}

int dattobd_expand_cow_file(unsigned int minor, uint64_t size)
{
	int ret;
	struct netlink_expand_cow_file_params params = {
		.size = size,
		.minor = minor,
	};
	struct netlink_request req;
	struct netlink_response resp;

	req.type = MSG_EXPAND_COW_FILE;
	req.expand_cow_file_params = &params;

	ret = datto_netlink_submit(&req, &resp);

	return ret;
}

int dattobd_reconfigure_auto_expand(unsigned int minor, uint64_t step_size, uint64_t reserved_space)
{
	int ret;
	struct netlink_reconfigure_auto_expand_params params = {
		.step_size = step_size,
		.reserved_space = reserved_space,
		.minor = minor,
	};
	struct netlink_request req;
	struct netlink_response resp;

	req.type = MSG_RECONFIGURE_AUTO_EXPAND;
	req.reconfigure_auto_expand_params = &params;

	ret = datto_netlink_submit(&req, &resp);

	return ret;
}