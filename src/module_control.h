// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 声明模块控制层使用的全局名称、参数以及主次设备号范围等共享定义。
 */

#ifndef MODULE_CONTROL_H_
#define MODULE_CONTROL_H_

// 名称相关宏
#define INFO_PROC_FILE "datto-info"
#define DRIVER_NAME "datto"
#define CONTROL_DEVICE_NAME "datto-ctl"
#define SNAP_DEVICE_NAME "datto%u"
#define BCS_DEVICE_NAME "dattobcs%u"
#define SNAP_COW_THREAD_NAME_FMT "datto_snap_cow%d"
#define SNAP_MRF_THREAD_NAME_FMT "datto_snap_mrf%d"
#define INC_THREAD_NAME_FMT "datto_inc%d"

// 模块全局参数
extern int dattobd_may_hook_syscalls;
extern unsigned long dattobd_cow_max_memory_default;
extern unsigned int dattobd_cow_fallocate_percentage_default;
extern unsigned int dattobd_max_snap_devices;

extern unsigned int highest_minor;
extern unsigned int lowest_minor;
extern int major;

#endif /* MODULE_CONTROL_H_ */
