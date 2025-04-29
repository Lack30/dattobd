// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Copyright (C) 2015 Datto Inc.
 */

#include "dattobd.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include "libdattobd.h"

#include <sys/socket.h>
#include <linux/netlink.h>

int datto_netlink_submit(struct netlink_request *req, struct netlink_response *resp)
{
	int sockfd, ret;
	struct sockaddr_nl local, remote;
	struct nlmsghdr *nlh = NULL;
	size_t req_size = sizeof(struct netlink_request);

	sockfd = socket(AF_NETLINK, SOCK_RAW, 25);
	if (sockfd == -1) {
		// printf("create socket failure! %s\n", strerror(errno));
		return 1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = 50;
	local.nl_groups = 0;
	if (bind(sockfd, (struct sockaddr *)&local, sizeof(local)) != 0) {
		// printf("bind() error!\n");
		ret = 1;
		goto error;
	}

	memset(&remote, 0, sizeof(remote));
	remote.nl_family = AF_NETLINK;
	remote.nl_pid = 0;
	remote.nl_groups = 0;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct nlmsghdr)));
	memset(nlh, 0, sizeof(struct nlmsghdr));
	nlh->nlmsg_len = NLMSG_SPACE(req_size);
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = NETLINK_USERSOCK;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = local.nl_pid;

	//printf("send to kernel!!\n");
	memcpy(NLMSG_DATA(nlh), req, req_size);
	ret = sendto(sockfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&remote,
				 sizeof(struct sockaddr_nl));
	if (ret < 0) {
		// printf("send to kernel error!\n");
		ret = 1;
		goto error;
	}

	//printf("recv from kernel!!\n");
	memset(nlh, 0, sizeof(struct nlmsghdr));
	ret = recvfrom(sockfd, nlh, NLMSG_LENGTH(sizeof(struct netlink_response)), 0, NULL, NULL);
	if (ret < 0) {
		// printf("recv from kernel error!\n");
		ret = 1;
		goto error;
	}
	resp = (struct netlink_response *)NLMSG_DATA(nlh);
	ret = resp->ret;

error:
	if (nlh)
		free((void *)nlh);

	if (sockfd)
		close(sockfd);

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

int dattobd_info(unsigned int minor, struct dattobd_info **info)
{
	int ret;
	struct netlink_info_params ip;
	struct netlink_request req;
	struct netlink_response resp;

	if (!info) {
		errno = EINVAL;
		return -1;
	}

	ip.minor = minor;

	req.type = MSG_DATTOBD_INFO;
	req.info_params = &ip;

	ret = datto_netlink_submit(&req, &resp);
	if (!ret)
		*info = resp.info->info;

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
		return resp.get_free->minor;
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