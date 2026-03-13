// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#ifndef TRACER_HELPER_H_
#define TRACER_HELPER_H_

#include "bio_helper.h"
#include "hints.h"
#include "includes.h"
#include "module_control.h"
#include "blkdev.h"

/* 遍历 snap_devices 的宏（使用前需对 dev 做空指针检查） */
#define tracer_for_each(dev, i)                                                                    \
    for (i = ACCESS_ONCE(lowest_minor), dev = ACCESS_ONCE(snap_devices[i]);                        \
         i <= ACCESS_ONCE(highest_minor); i++, dev = ACCESS_ONCE(snap_devices[i]))
#define tracer_for_each_full(dev, i)                                                               \
    for (i = 0, dev = ACCESS_ONCE(snap_devices[i]); i < dattobd_max_snap_devices;                  \
         i++, dev = ACCESS_ONCE(snap_devices[i]))

/* 跟踪结构的底层设备队列与 bio 的队列一致时为 true */
#define tracer_queue_matches_bio(dev, bio)                                                         \
    (bdev_get_queue((dev)->sd_base_dev->bdev) == dattobd_bio_get_queue(bio))

/* 跟踪结构的扇区范围包含该 bio 的扇区时为 true */
#define tracer_sector_matches_bio(dev, bio)                                                        \
    (bio_sector(bio) >= (dev)->sd_sect_off && bio_sector(bio) < (dev)->sd_sect_off + (dev)->sd_size)

/**
 * tracer_is_bio_for_dev() - 判断 bio 是否针对给定 snap_device。
 *
 * 当 bio 的队列与设备队列及分区一致、bio 有大小、跟踪结构处于非失败状态、
 * 且设备扇区范围包含该 bio 时返回 true。
 *
 * @dev: 要与之比较的 snap_device。
 * @bio: 要与之比较的 bio。
 *
 * Return: 满足上述条件且 bio 针对 dev 时为 true，否则 false。
 */
bool tracer_is_bio_for_dev(struct snap_device *dev, struct bio *bio);

/**
 * tracer_is_bio_for_dev_only_queue() - 仅按队列判断 bio 是否针对给定 snap_device。
 *
 * bio 的队列与设备队列一致时返回 true。
 *
 * @dev: 要与之比较的 snap_device。
 * @bio: 要与之比较的 bio。
 *
 * Return: bio 原本属于 dev 的队列时为 true，否则 false。
 */
bool tracer_is_bio_for_dev_only_queue(struct snap_device *dev, struct bio *bio);

/**
 * tracer_should_trace_bio() - 判断给定 bio 是否应被跟踪。
 *
 * Return: dev 非空且 bio 有大小、为写请求、跟踪结构处于非失败状态、
 *         设备扇区范围包含该 bio 时返回 true。
 */
bool tracer_should_trace_bio(struct snap_device *dev, struct bio *bio);

struct snap_device;

/**
 * tracer_read_fail_state() - 返回当前为 &struct snap_device 设置的错误码。
 * @dev: &struct snap_device 对象指针。
 *
 * Return: 错误码，0 表示未设置错误。
 */
int tracer_read_fail_state(const struct snap_device *dev);

/**
 * tracer_set_fail_state() - 为 &struct snap_device 设置错误码。
 *
 * @dev: &struct snap_device 对象指针。
 * @error: 要设置的错误码。
 */
void tracer_set_fail_state(struct snap_device *dev, int error);

#endif /* TRACER_HELPER_H_ */
