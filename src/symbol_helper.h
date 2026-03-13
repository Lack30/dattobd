// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Datto Inc.
 */

#ifndef SYMBOL_LOOKUP_H_
#define SYMBOL_LOOKUP_H_

#include <linux/types.h>

/**
 * struct dattobd_symbol_addrs - 内核符号地址表
 * @blk_mq_submit_bio: blk_mq_submit_bio 函数地址
 * @kfree: kfree 函数地址
 * @vm_area_alloc: vm_area_alloc 函数地址
 * @vm_area_free: vm_area_free 函数地址
 * @insert_vm_struct: insert_vm_struct 函数地址
 * @vm_area_cachep: vm_area_cachep 变量地址
 * @get_active_super: get_active_super 函数地址
 * @vma_lock_cachep: vma_lock_cachep 变量地址
 * @sys_mount: sys_mount 函数地址
 * @sys_umount: sys_umount 函数地址
 * @sys_oldumount: sys_oldumount 函数地址
 *
 * 存储所有需要动态查找的内核符号地址
 */
struct dattobd_symbol_addrs {
    unsigned long blk_mq_submit_bio;
    unsigned long kfree;
    unsigned long vm_area_alloc;
    unsigned long vm_area_free;
    unsigned long insert_vm_struct;
    unsigned long vm_area_cachep;
    unsigned long get_active_super;
    unsigned long vma_lock_cachep;
    unsigned long sys_mount;
    unsigned long sys_umount;
    unsigned long sys_oldumount;
};

/* 全局符号地址表 */
extern struct dattobd_symbol_addrs dattobd_symbols;

/**
 * dattobd_symbol_lookup_init() - 初始化符号查找
 *
 * 在模块加载时调用，查找所有需要的内核符号地址
 *
 * Return:
 * * 0 - 成功
 * * -ENOENT - 必需的符号未找到
 */
int dattobd_symbol_helper_init(void);

/**
 * dattobd_lookup_symbol() - 查找单个符号地址
 * @name: 符号名称
 *
 * 使用 kprobe 或 kallsyms_lookup_name 查找符号地址
 *
 * Return: 符号地址，未找到返回 0
 */
unsigned long dattobd_lookup_symbol(const char *name);

/**
 * dattobd_get_kfree_offset() - 获取 kfree 的偏移校准值
 *
 * 用于计算其他内核函数的相对地址
 *
 * Return: kfree 当前地址与编译时地址的偏移差
 */
long long dattobd_get_kfree_offset(void);

#endif /* SYMBOL_LOOKUP_H_ */
