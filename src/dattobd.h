/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */

/*
 * Copyright (C) 2015-2022 Datto Inc.
 */

#ifndef DATTOBD_H_
#define DATTOBD_H_

#ifndef __KERNEL__
#include <stdint.h>
#endif

#include <linux/limits.h>
#include <linux/types.h>

#define DATTOBD_VERSION "0.12.0"
#define DATTOBD_NETLINK_UNIT 25

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

#define MAX_PAYLOAD 1024

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

struct destroy_params {
	unsigned int minor; // requested minor number of the device
};

struct transition_inc_params {
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

enum msg_type {
	MSG_PING = 1,
	MSG_SETUP_SNAP = 2,
	MSG_RELOAD_SNAP = 3,
	MSG_RELOAD_INC = 4,
	MSG_DESTROY = 5,
	MSG_TRANSITION_INC = 6,
	MSG_TRANSITION_SNAP = 7,
	MSG_RECONFIGURE = 8,
	MSG_DATTOBD_INFO = 9,
	MSG_GET_FREE = 10,
	MSG_EXPAND_COW_FILE = 11,
	MSG_RECONFIGURE_AUTO_EXPAND = 12,
};

struct netlink_request {
	enum msg_type type;
	struct setup_params *setup_params;
	struct reload_params *reload_params;
	struct destroy_params *destroy_params;
	struct transition_inc_params *transition_inc_params;
	struct transition_snap_params *transition_snap_params;
	struct reconfigure_params *reconfigure_params;
	struct dattobd_info *info_params;
	struct expand_cow_file_params *expand_cow_file_params;
	struct reconfigure_auto_expand_params *reconfigure_auto_expand_params;
};

struct get_free_response {
	unsigned int minor; // requested minor number of the device
};

struct netlink_response {
	int ret;
	enum msg_type type;

	union {
		struct get_free_response get_free;
	};
};

#endif /* DATTOBD_H_ */
