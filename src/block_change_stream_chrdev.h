// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

/*
 * 声明 block change stream 字符设备的注册与注销接口。
 */

#ifndef BLOCK_CHANGE_STREAM_CHRDEV_H_
#define BLOCK_CHANGE_STREAM_CHRDEV_H_

/**
 * register_block_change_stream_chrdev() - 注册 block change stream 字符设备。
 *
 * Return:
 * * 0 - 成功。
 * * !0 - 表示错误的 errno。
 */
int register_block_change_stream_chrdev(void);

/**
 * unregister_block_change_stream_chrdev() - 注销 block change stream 字符设备。
 */
void unregister_block_change_stream_chrdev(void);

#endif /* BLOCK_CHANGE_STREAM_CHRDEV_H_ */
