// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 声明模块内各类快照与增量处理线程的入口函数。
 */

#ifndef MODULE_THREADS_H_
#define MODULE_THREADS_H_

int inc_sset_thread(void *data);
int snap_cow_thread(void *data);
int snap_mrf_thread(void *data);

#endif /* MODULE_THREADS_H_ */
