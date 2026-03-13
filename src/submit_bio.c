// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 提供将 bio 绕过驱动钩子并直接提交到真实设备的提交通道实现。
 */

#include "submit_bio.h"

#include "bio_helper.h" /* 用于定义 USE_BDOPS_SUBMIT_BIO */
#include "callback_refs.h"
#include "includes.h"
#include "logging.h"
#include "paging_helper.h"
#include "snap_device.h"

#ifdef USE_BDOPS_SUBMIT_BIO

/*
 * ftrace 依赖每个函数前导代码调用 __fentry__（汇编片段）以触发回调。若需递归调用
 * 而不触发 ftrace，需跳过此前导。栈指针调整紧接在该调用之后。
 */
blk_qc_t (*dattobd_submit_bio_noacct_passthrough)(struct bio *) =
        (blk_qc_t(*)(struct bio *))((unsigned long)(submit_bio_noacct) + FENTRY_CALL_INSTR_BYTES);

int dattobd_submit_bio_real(struct snap_device *dev, struct bio *bio)
{
    return dattobd_submit_bio_noacct_passthrough(bio);
}

#endif
