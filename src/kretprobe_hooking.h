// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#ifndef KRETPROBE_HOOKING_H_
#define KRETPROBE_HOOKING_H_

#include <linux/mount.h>
#include <linux/version.h>
#include "logging.h"
#include "includes.h"
#include "bdev_state_handler.h"
#include <linux/kprobes.h>

#ifdef HAVE_UAPI_MOUNT_H
#include <uapi/linux/mount.h>
#endif

/***************************KRETPROBE HOOKING***************************/

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct mount_params {
	char dev_name[PATH_MAX];
	char dir_name[PATH_MAX];
	char fs_type[64];
	unsigned long flags;
	unsigned int idx;
	int ret;
};

struct umount_params {
	char dir_name[PATH_MAX];
	int flags;
	unsigned int idx;
	int ret;
};

struct probe_entry {
	struct rb_node node;
	unsigned long key;
	void *data;
};

struct probe_pool {
	struct rb_root root;
	spinlock_t lock;
};

void probe_pool_init(struct probe_pool *p);
void probe_pool_clear(struct probe_pool *p);

int probe_pool_insert(struct probe_pool *p, unsigned long key, void *data);
void *probe_pool_erase(struct probe_pool *p, unsigned long key);

#define KRETPROBE(_name, _entry_handler, _ret_handler)                                             \
	{                                                                                              \
		.kp.symbol_name = (_name), .handler = (_ret_handler), .entry_handler = (_entry_handler),   \
		.maxactive = 8                                                                             \
	}

static inline unsigned long pt_regs_params(struct pt_regs *regs, int idx)
{
	unsigned long val;
#if defined(CONFIG_ARM64) || defined(CONFIG_ARM)
	val = (idx == 31) ? 0 : regs->regs[idx];
#else
	switch (idx) {
	case 0:
		val = regs->di;
		break;
	case 1:
		val = regs->si;
		break;
	case 2:
		val = regs->dx;
		break;
	case 3:
		val = regs->r10;
		break;
	case 4:
		val = regs->r8;
		break;
	default:
		val = 0;
		break;
	}
#endif

	return val;
}

static inline unsigned long pt_regs_returns(struct pt_regs *regs)
{
	unsigned long val;
#if defined(CONFIG_ARM64) || defined(CONFIG_ARM)
	val = regs->regs[0];
#else
	val = regs->ax;
#endif
	return val;
}

int register_kretprobe_hooks(void);
int unregister_kretprobe_hooks(void);

#endif /* KRETPROBE_HOOKING_H_ */