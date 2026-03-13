// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022-2023 Datto Inc.
 */

/*
 * 声明真实设备 submit_bio 适配类型与直通提交通道接口。
 */

#ifndef SUBMIT_BIO_H_
#define SUBMIT_BIO_H_

#include "includes.h"
#include "mrf.h"
#include "bio_helper.h" // needed for USE_BDOPS_SUBMIT_BIO to be defined

struct snap_device;

#ifdef USE_BDOPS_SUBMIT_BIO

/**
 * submit_bio_fn() - submit_bio 函数原型，在 5.9+ 内核上用作拦截 I/O 的钩子。
 */
typedef MRF_RETURN_TYPE(submit_bio_fn)(struct bio *bio);

/**
 * dattobd_submit_bio_real() - 将给定 bio 提交到真实设备（而非本驱动）。
 *
 * @dev: 保存设备状态的 snap_device 指针。
 * @bio: 描述进行中 I/O 的 bio 指针。
 *
 * Return: 0 表示成功，非 0 表示错误。
 */
int dattobd_submit_bio_real(struct snap_device *dev, struct bio *bio);

#endif // USE_BDOPS_SUBMIT_BIO
#endif // SUBMIT_BIO_H_
