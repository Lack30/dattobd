// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#ifndef CALLBACK_REFS_H_
#define CALLBACK_REFS_H_

#include "includes.h"
#include "bio_helper.h"
#include "bio_request_callback.h"

#ifndef USE_BDOPS_SUBMIT_BIO

/**
 * mrf_tracking_init() - 初始化 mrf 跟踪。
 *
 * 初始化用于 mrf 引用计数的哈希表。
 */
void mrf_tracking_init(void);

/**
 * mrf_get() - 增加指定 mrf 的引用计数。
 *
 * @disk: 被跟踪的块设备。
 * @fn: 要增加引用计数的 mrf。
 *
 * Return: 成功返回 0，否则非 0。
 */
int mrf_get(const struct gendisk *disk, BIO_REQUEST_CALLBACK_FN *fn);

/**
 * mrf_put() - 减少引用计数并返回 mrf。
 *
 * @disk: 被跟踪的块设备。
 *
 * Return: 返回该块设备的 mrf，错误时返回 NULL。
 */
const BIO_REQUEST_CALLBACK_FN *mrf_put(struct gendisk *disk);

#endif // USE_BDOPS_SUBMIT_BIO
#endif // CALLBACK_REFS_H_
