// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2022 Datto Inc.

/**
 * DOC: bio_request_callback 头文件
 *
 * 定义提交 I/O 请求所需的各类机制与类型。
 *
 * 不同 Linux 版本使用不同的类型与回调向内核提交进行中的 I/O。
 *
 * 本头文件提供统一的接口以完成上述行为。
 */

#ifndef BIO_REQUEST_CALLBACK_H_INCLUDE
#define BIO_REQUEST_CALLBACK_H_INCLUDE

#include "bio_helper.h" // needed for USE_BDOPS_SUBMIT_BIO to be defined
#include "includes.h"
#include "mrf.h"
#include "submit_bio.h"

#ifdef USE_BDOPS_SUBMIT_BIO

#ifdef CONFIG_X86
/* x86_64 上 `call __fentry__` 指令长度：1 字节 op + 4 字节相对地址 */
#define FENTRY_CALL_INSTR_BYTES 5
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
/* ARM 上 `bl __fentry__` 指令长度：4 字节 op + 4 字节相对地址 */
#define FENTRY_CALL_INSTR_BYTES 4
#else
#pragma error "Unsupported architecture"
#endif

#define BIO_REQUEST_CALLBACK_FN submit_bio_fn
#define SUBMIT_BIO_REAL dattobd_call_mrf_real
#else
#define BIO_REQUEST_CALLBACK_FN make_request_fn
#define SUBMIT_BIO_REAL dattobd_call_mrf_real
#define GET_BIO_REQUEST_TRACKING_PTR dattobd_get_bd_mrf
#define GET_BIO_REQUEST_TRACKING_PTR_GD dattobd_get_gd_mrf
#endif

#endif
