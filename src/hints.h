// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 定义少量编译提示与访问兼容宏，统一低层语义细节。
 */

#ifndef HINTS_H_
#define HINTS_H_

/* 编译期提示宏 */
#define MAYBE_UNUSED(x) (void)(x)

#ifndef ACCESS_ONCE

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

#endif

#endif /* HINTS_H_ */
