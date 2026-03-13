// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 声明跨架构的页保护开关接口，用于临时关闭并恢复内核页写保护。
 */

#ifndef PAGING_HELPER_H_
#define PAGING_HELPER_H_

void disable_page_protection(unsigned long *cr0);
void reenable_page_protection(unsigned long *cr0);

#endif /* PAGING_HELPER_H_ */
