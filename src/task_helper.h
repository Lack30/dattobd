// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 声明 task_work_flush() 的兼容接口，用于强制执行延后的任务工作项。
 */

#ifndef TASK_WORK_HELPER_H_
#define TASK_WORK_HELPER_H_

/*****************************TASK WORK FUNCTIONS****************************/

/* task_work_run() 的重实现，用于强制 fput() 和 mntput() 同步执行其工作。 */
#ifdef HAVE_TASK_STRUCT_TASK_WORKS_HLIST
void task_work_flush(void);
#elif defined HAVE_TASK_STRUCT_TASK_WORKS_CB_HEAD
void task_work_flush(void);
#else
#define task_work_flush()
#endif

#endif /* TASK_WORK_HELPER_H_ */
