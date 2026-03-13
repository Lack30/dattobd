// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Datto Inc.
 */

#include "symbol_helper.h"
#include "blkdev.h"
#include "includes.h"
#include "logging.h"
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

/* 全局符号地址表 */
struct dattobd_symbol_addrs dattobd_symbols = { 0 };

/* 符号名称与地址映射表 */
static const struct {
    const char *name;
    unsigned long *addr;
    bool required;
} symbol_table[] = {
    // 必需符号
    { "kfree", &dattobd_symbols.kfree, true },

    // 可选符号 - 用于块设备 I/O
    { "blk_mq_submit_bio", &dattobd_symbols.blk_mq_submit_bio, false },

    // 可选符号 - 用于 VMA 操作
    { "vm_area_alloc", &dattobd_symbols.vm_area_alloc, false },
    { "vm_area_free", &dattobd_symbols.vm_area_free, false },
    { "insert_vm_struct", &dattobd_symbols.insert_vm_struct, false },
    { "vm_area_cachep", &dattobd_symbols.vm_area_cachep, false },
    { "vma_lock_cachep", &dattobd_symbols.vma_lock_cachep, false },

    // 可选符号 - 用于超级块操作
    { "get_active_super", &dattobd_symbols.get_active_super, false },

    // 可选符号 - 用于系统调用钩子
    { "sys_mount", &dattobd_symbols.sys_mount, false },
    { "sys_umount", &dattobd_symbols.sys_umount, false },
    { "sys_oldumount", &dattobd_symbols.sys_oldumount, false },

    { NULL, NULL, false }
};

/**
 * dattobd_lookup_symbol() - 查找单个符号地址
 * @name: 符号名称
 *
 * 使用 kprobe 查找符号地址
 *
 * Return: 符号地址，未找到返回 0
 */
unsigned long dattobd_lookup_symbol(const char *name)
{
    unsigned long addr = 0;
    struct kprobe kp = {
        .symbol_name = name,
    };

    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
        LOG_DEBUG("found symbol '%s' at 0x%lx via kprobe", name, addr);
    }

    return addr;
}

/**
 * dattobd_symbol_helper_init() - 初始化符号助手
 *
 * 在模块加载时调用，查找所有需要的内核符号地址
 *
 * Return:
 * * 0 - 成功
 * * -ENOENT - 必需的符号未找到
 */
int dattobd_symbol_helper_init(void)
{
    int i;
    int required_missing = 0;
    int optional_missing = 0;

    LOG_DEBUG("initializing symbol lookup");

    for (i = 0; symbol_table[i].name != NULL; i++) {
        *symbol_table[i].addr = dattobd_lookup_symbol(symbol_table[i].name);

        if (*symbol_table[i].addr == 0) {
            if (symbol_table[i].required) {
                LOG_ERROR(-ENOENT, "required symbol '%s' not found", symbol_table[i].name);
                required_missing++;
            } else {
                LOG_DEBUG("optional symbol '%s' not found, some features may be disabled",
                          symbol_table[i].name);
                optional_missing++;
            }
        }
    }

    if (required_missing > 0) {
        LOG_ERROR(-ENOENT, "%d required symbols not found", required_missing);
        return -ENOENT;
    }

    if (optional_missing > 0) {
        LOG_DEBUG("symbol lookup complete: %d optional symbols not found", optional_missing);
    }

    return 0;
}

/**
 * dattobd_get_kfree_offset() - 获取 kfree 的偏移校准值
 *
 * 用于计算其他内核函数的相对地址。
 * 由于内核地址可能因 KASLR 而变化，需要计算偏移差。
 *
 * Return: kfree 当前地址与编译时地址的偏移差
 */
long long dattobd_get_kfree_offset(void)
{
    if (dattobd_symbols.kfree == 0) {
        return 0;
    }
    return (long long)((void *)kfree - (void *)dattobd_symbols.kfree);
}
