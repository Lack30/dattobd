// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2015-2023 Datto Inc.
 */

/*
 * 集中引入模块实现普遍依赖的 Linux 内核头文件。
 */

#ifndef DATTOBD_INCLUDES_H_
#define DATTOBD_INCLUDES_H_

#include <asm/div64.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/buffer_head.h>
#include <linux/ftrace.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/fiemap.h>
#include <linux/types.h>
#include <linux/rwsem.h>
#include <linux/statfs.h>
#include <linux/string.h>

#endif
