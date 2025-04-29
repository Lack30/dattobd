/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */

/*
 * Copyright (C) 2015-2022 Datto Inc.
 */

#ifndef DATTOBD_H_
#define DATTOBD_H_

#ifndef __KERNEL__
#include <stdint.h>
#endif

#include <linux/ioctl.h>
#include <linux/limits.h>
#include <linux/types.h>

#define DATTOBD_VERSION "0.12.0"
#define DATTO_IOCTL_MAGIC 0x91

struct setup_params {
	char *bdev; // name of block device to snapshot
	char *cow; // name of cow file for snapshot
	unsigned long fallocated_space; // space allocated to the cow file (in megabytes)
	unsigned long cache_size; // maximum cache size (in bytes)
	unsigned int minor; // requested minor number of the device
};

struct reload_params {
	char *bdev; // name of block device to snapshot
	char *cow; // name of cow file for snapshot
	unsigned long cache_size; // maximum cache size (in bytes)
	unsigned int minor; // requested minor number of the device
};

struct transition_snap_params {
	char *cow; // name of cow file for snapshot
	unsigned long fallocated_space; // space allocated to the cow file (in bytes)
	unsigned int minor; // requested minor
};

struct reconfigure_params {
	unsigned long cache_size; // maximum cache size (in bytes)
	unsigned int minor; // requested minor number of the device
};

struct expand_cow_file_params {
	uint64_t size; // size in mib

	unsigned int minor; // minor to extend
};

struct reconfigure_auto_expand_params {
	uint64_t step_size; // step size in mib
	uint64_t reserved_space; // reserved space in mib

	unsigned int minor; // minor to configure
};

#define COW_UUID_SIZE 16
#define COW_BLOCK_LOG_SIZE 12
#define COW_BLOCK_SIZE (1 << COW_BLOCK_LOG_SIZE)
#define COW_HEADER_SIZE 4096
#define COW_MAGIC ((uint32_t)4776)
#define COW_CLEAN 0
#define COW_INDEX_ONLY 1
#define COW_VMALLOC_UPPER 2

#define COW_VERSION_0 0
#define COW_VERSION_CHANGED_BLOCKS 1

/**
 * struct cow_header - Encapsulates the values stored at the beginning of the
 * COW file.
 */
struct cow_header {
	uint32_t magic; // COW header magic
	uint32_t flags; // COW file flags
	uint64_t fpos; // current file offset
	uint64_t fsize; // file size
	uint64_t seqid; // seqential id of snapshot (starts at 1)
	uint8_t uuid[COW_UUID_SIZE]; // uuid for this series of snapshots
	uint64_t version; // version of cow file format
	uint64_t nr_changed_blocks; // number of changed blocks since last snapshot
};

struct dattobd_info {
	unsigned int minor;
	unsigned long state;
	int error;
	unsigned long cache_size;
	unsigned long long falloc_size;
	unsigned long long seqid;
	char uuid[COW_UUID_SIZE];
	char cow[PATH_MAX];
	char bdev[PATH_MAX];
	unsigned long long version;
	unsigned long long nr_changed_blocks;
};

#define IOCTL_SETUP_SNAP _IOW(DATTO_IOCTL_MAGIC, 1, struct setup_params)
#define IOCTL_RELOAD_SNAP _IOW(DATTO_IOCTL_MAGIC, 2, struct reload_params)
#define IOCTL_RELOAD_INC _IOW(DATTO_IOCTL_MAGIC, 3, struct reload_params)
#define IOCTL_DESTROY _IOW(DATTO_IOCTL_MAGIC, 4, unsigned int)
#define IOCTL_TRANSITION_INC _IOW(DATTO_IOCTL_MAGIC, 5, unsigned int)
#define IOCTL_TRANSITION_SNAP _IOW(DATTO_IOCTL_MAGIC, 6, struct transition_snap_params)
#define IOCTL_RECONFIGURE _IOW(DATTO_IOCTL_MAGIC, 7, struct reconfigure_params)
#define IOCTL_DATTOBD_INFO _IOR(DATTO_IOCTL_MAGIC, 8, struct dattobd_info)
#define IOCTL_GET_FREE _IOR(DATTO_IOCTL_MAGIC, 9, int)
#define IOCTL_EXPAND_COW_FILE _IOW(DATTO_IOCTL_MAGIC, 10, struct expand_cow_file_params)
#define IOCTL_RECONFIGURE_AUTO_EXPAND                                                              \
	_IOW(DATTO_IOCTL_MAGIC, 11, struct reconfigure_auto_expand_params)

struct netlink_setup_params {
	char *bdev; // name of block device to snapshot
	char *cow; // name of cow file for snapshot
	unsigned long fallocated_space; // space allocated to the cow file (in megabytes)
	unsigned long cache_size; // maximum cache size (in bytes)
	unsigned int minor; // requested minor number of the device
};

struct netlink_reload_params {
	char *bdev; // name of block device to snapshot
	char *cow; // name of cow file for snapshot
	unsigned long cache_size; // maximum cache size (in bytes)
	unsigned int minor; // requested minor number of the device
};

struct netlink_destroy_params {
	unsigned int minor; // requested minor number of the device
};

struct netlink_transition_inc_params {
	unsigned int minor; // requested minor number of the device
};

struct netlink_transition_snap_params {
	char *cow; // name of cow file for snapshot
	unsigned long fallocated_space; // space allocated to the cow file (in bytes)
	unsigned int minor; // requested minor
};

struct netlink_reconfigure_params {
	unsigned long cache_size; // maximum cache size (in bytes)
	unsigned int minor; // requested minor number of the device
};

struct netlink_info_params {
	unsigned int minor;
};

struct netlink_expand_cow_file_params {
	uint64_t size; // size in mib

	unsigned int minor; // minor to extend
};

struct netlink_reconfigure_auto_expand_params {
	uint64_t step_size; // step size in mib
	uint64_t reserved_space; // reserved space in mib

	unsigned int minor; // minor to configure
};

enum msg_type {
	MSG_SETUP_SNAP = 1,
	MSG_RELOAD_SNAP = 2,
	MSG_RELOAD_INC = 3,
	MSG_DESTROY = 4,
	MSG_TRANSITION_INC = 5,
	MSG_TRANSITION_SNAP = 6,
	MSG_RECONFIGURE = 7,
	MSG_DATTOBD_INFO = 8,
	MSG_GET_FREE = 9,
	MSG_EXPAND_COW_FILE = 10,
	MSG_RECONFIGURE_AUTO_EXPAND = 11,
};

struct netlink_request {
	enum msg_type type;
	struct netlink_setup_params *setup_params;
	struct netlink_reload_params *reload_params;
	struct netlink_destroy_params *destroy_params;
	struct netlink_transition_inc_params *transition_inc_params;
	struct netlink_transition_snap_params *transition_snap_params;
	struct netlink_reconfigure_params *reconfigure_params;
	struct netlink_info_params *info_params;
	struct netlink_expand_cow_file_params *expand_cow_file_params;
	struct netlink_reconfigure_auto_expand_params *reconfigure_auto_expand_params;
};

struct netlink_dattobd_info {
	struct dattobd_info *info;
};

struct netlink_get_free_response {
	unsigned int minor; // requested minor number of the device
};

struct netlink_response {
	enum msg_type type;
	int ret;

	struct netlink_dattobd_info *info;
	struct netlink_get_free_response *get_free;
};

#endif /* DATTOBD_H_ */
