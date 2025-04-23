// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "includes.h"
#include "paging_helper.h"

#ifdef CONFIG_ARM64 // 检查是否为 ARM64 平台

/**
 * disable_page_protection() - 禁用页面保护（ARM64 平台）。
 *
 * ARM64 使用 SCTLR_EL1 寄存器的 WP 位来控制写保护。
 *
 * @sctlr: 用于保存修改前的 SCTLR_EL1 寄存器值。
 */
void disable_page_protection(unsigned long *sctlr)
{
	asm volatile("mrs %0, sctlr_el1" : "=r"(*sctlr)); // 读取 SCTLR_EL1
	asm volatile("msr sctlr_el1, %0" : : "r"(*sctlr & ~0x1)); // 清除 WP 位
	isb(); // 确保指令同步
}

/**
 * reenable_page_protection() - 恢复页面保护（ARM64 平台）。
 *
 * @sctlr: 修改前保存的 SCTLR_EL1 寄存器值。
 */
void reenable_page_protection(unsigned long *sctlr)
{
	asm volatile("msr sctlr_el1, %0" : : "r"(*sctlr)); // 恢复原始 SCTLR_EL1 值
	isb(); // 确保指令同步
}

#elif defined(CONFIG_X86)

#ifndef X86_CR0_WP
#define X86_CR0_WP (1UL << 16)
#endif

static inline void wp_cr0(unsigned long cr0)
{
#ifdef USE_BDOPS_SUBMIT_BIO
	__asm__ __volatile__("mov %0, %%cr0" : "+r"(cr0));
#else
	write_cr0(cr0);
#endif
}

void disable_page_protection(unsigned long *cr0)
{
	*cr0 = read_cr0();
	wp_cr0(*cr0 & ~X86_CR0_WP);
}

void reenable_page_protection(unsigned long *cr0)
{
	write_cr0(*cr0);
}

#endif // __aarch64__