/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Copyright (C) 2015 Datto Inc.
 */

/*
 * 声明 libdattobd 对外提供的快照管理与查询 API。
 */

#ifndef LIBDATTOBD_H_
#define LIBDATTOBD_H_

#include "dattobd.h"

#ifdef __cplusplus
extern "C" {
#endif

int dattobd_ping(void);

int dattobd_setup_snapshot(unsigned int minor, char *bdev, char *cow,
                           unsigned long fallocated_space, unsigned long cache_size);

int dattobd_reload_snapshot(unsigned int minor, char *bdev, char *cow, unsigned long cache_size);

int dattobd_reload_incremental(unsigned int minor, char *bdev, char *cow, unsigned long cache_size);

int dattobd_destroy(unsigned int minor);

int dattobd_transition_incremental(unsigned int minor);

int dattobd_transition_snapshot(unsigned int minor, char *cow, unsigned long fallocated_space);

int dattobd_reconfigure(unsigned int minor, unsigned long cache_size);

int dattobd_info(unsigned int minor, struct dattobd_info *info);

int dattobd_block_change_stream_status(unsigned int minor,
                                       struct block_change_stream_status *status);

int dattobd_expand_cow_file(unsigned int minor, uint64_t size);

int dattobd_reconfigure_auto_expand(unsigned int minor, uint64_t step_size,
                                    uint64_t reserved_space);

/**
 * 获取第一个可用的次设备号。
 *
 * @returns 有可用 minor 时返回非负整数，否则 -1
 */
int dattobd_get_free_minor(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBDATTOBD_H_ */
