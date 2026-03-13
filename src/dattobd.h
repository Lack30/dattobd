/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */

/*
 * Copyright (C) 2015-2022 Datto Inc.
 */

#ifndef DATTOBD_H_
#define DATTOBD_H_

#ifndef __KERNEL__
#include <stdint.h>
#endif

#include <linux/limits.h>
#include <linux/types.h>

#define DATTOBD_VERSION "0.12.0"
#define DATTOBD_NETLINK_UNIT 25

#define COW_UUID_SIZE 16
#define COW_BLOCK_LOG_SIZE 12
#define COW_BLOCK_SIZE (1 << COW_BLOCK_LOG_SIZE)
#define COW_HEADER_SIZE 4096
#define COW_MAGIC ((uint32_t)4776)
#define COW_CLEAN 0
#define COW_INDEX_ONLY 1
#define COW_VMALLOC_UPPER 2

#define COW_VERSION_0 0
#define COW_VERSION_CHANGED_BLOCKS 1

#define OP_WRITE_SIZE 512
#define MAX_PAYLOAD 4096

/**
 * struct cow_header - COW 文件开头的元数据。
 */
struct cow_header {
    uint32_t magic; // COW 头魔数
    uint32_t flags; // COW 文件标志
    uint64_t fpos; // 当前文件偏移
    uint64_t fsize; // 文件大小
    uint64_t seqid; // 快照顺序 id（从 1 开始）
    uint8_t uuid[COW_UUID_SIZE]; // 本系列快照的 uuid
    uint64_t version; // COW 文件格式版本
    uint64_t nr_changed_blocks; // 自上次快照以来变更块数
};

struct dattobd_info {
    unsigned int minor;
    unsigned long state;
    int error;
    unsigned long cache_size;
    unsigned long long falloc_size;
    unsigned long long seqid;
    char uuid[COW_UUID_SIZE];
    char cow[PATH_MAX];
    char bdev[PATH_MAX];
    unsigned long long version;
    unsigned long long nr_changed_blocks;
};

struct dattobd_netlink_client {
    int pid;
    unsigned long state;
};

struct dattobd_watcher {
    int pid;
    char *mnt;

    unsigned long state;
    int error;
    unsigned long long seqid;
    unsigned long long nr_changed_op;
};

struct setup_params {
    char *bdev; // 要快照的块设备名
    char *cow; // 快照用 COW 文件名
    unsigned long fallocated_space; // COW 文件预分配空间（兆字节）
    unsigned long cache_size; // 最大缓存大小（字节）
    unsigned int minor; // 请求的设备次设备号
};

struct reload_params {
    char *bdev; // 要快照的块设备名
    char *cow; // 快照用 COW 文件名
    unsigned long cache_size; // 最大缓存大小（字节）
    unsigned int minor; // 请求的设备次设备号
};

struct destroy_params {
    unsigned int minor; // 请求的设备次设备号
};

struct transition_inc_params {
    unsigned int minor; // 请求的设备次设备号
};

struct transition_snap_params {
    char *cow; // 快照用 COW 文件名
    unsigned long fallocated_space; // COW 文件预分配空间（字节）
    unsigned int minor; // 请求的次设备号
};

struct reconfigure_params {
    unsigned long cache_size; // 最大缓存大小（字节）
    unsigned int minor; // 请求的设备次设备号
};

struct expand_cow_file_params {
    uint64_t size; // 扩展大小（MiB）
    unsigned int minor; // 要扩展的设备次设备号
};

struct reconfigure_auto_expand_params {
    uint64_t step_size; // 步长（MiB）
    uint64_t reserved_space; // 保留空间（MiB）
    unsigned int minor; // 要配置的次设备号
};

struct vfs_watcher_params {
    unsigned int minor;
};

enum msg_type {
    MSG_PING = 1,
    MSG_SETUP_SNAP = 2,
    MSG_RELOAD_SNAP = 3,
    MSG_RELOAD_INC = 4,
    MSG_DESTROY = 5,
    MSG_TRANSITION_INC = 6,
    MSG_TRANSITION_SNAP = 7,
    MSG_RECONFIGURE = 8,
    MSG_DATTOBD_INFO = 9,
    MSG_GET_FREE = 10,
    MSG_EXPAND_COW_FILE = 11,
    MSG_RECONFIGURE_AUTO_EXPAND = 12,
    MSG_OP_WATCH = 13,
};

struct netlink_request {
    enum msg_type type;
    struct setup_params *setup_params;
    struct reload_params *reload_params;
    struct destroy_params *destroy_params;
    struct transition_inc_params *transition_inc_params;
    struct transition_snap_params *transition_snap_params;
    struct reconfigure_params *reconfigure_params;
    struct dattobd_info *info_params;
    struct expand_cow_file_params *expand_cow_file_params;
    struct reconfigure_auto_expand_params *reconfigure_auto_expand_params;
    struct vfs_watcher_params *vfs_watcher_params;
};

enum op_type {
    OP_RELAY = 1,
    OP_WRITE = 2,
    OP_RENAME = 3,
    OP_UNLINK = 4,
    OP_SYMLINK = 5,
    OP_MKDIR = 6,
    OP_RMDIR = 7,
    OP_CHOWN = 8,
    OP_CHMOD = 9,
};

struct get_free_response {
    unsigned int minor; // 请求的设备次设备号
};

struct fs_op_vfs_write {
    unsigned int minor;
    unsigned long long timestamp; // 操作时间戳
    char path[PATH_MAX]; // 文件路径
    unsigned long i_ino; // inode 号
    unsigned long offset; // 文件内偏移
    unsigned long len; // 数据长度
    char buf[OP_WRITE_SIZE];
};

struct fs_op_vfs_rename {
    unsigned int minor;
    unsigned long long timestamp; // 操作时间戳
    unsigned long i_ino; // inode 号
    char old_path[PATH_MAX]; // 文件原路径
    char new_path[PATH_MAX]; // 文件新路径
};

struct fs_op_vfs_unlink {
    unsigned int minor;
    unsigned long long timestamp; // 操作时间戳
    unsigned long i_ino; // inode 号
    char path[PATH_MAX]; // 文件路径
};

struct fs_op_vfs_symlink {
    unsigned int minor;
    unsigned long long timestamp; // 操作时间戳
    unsigned long i_ino; // inode 号
    char old_path[PATH_MAX]; // 文件原路径
    char new_path[PATH_MAX]; // 文件新路径
};

struct fs_op_vfs_mkdir {
    unsigned int minor;
    unsigned long long timestamp;
    unsigned long i_ino;
    char path[PATH_MAX];
};

struct fs_op_vfs_rmdir {
    unsigned int minor;
    unsigned long long timestamp;
    unsigned long i_ino;
    char path[PATH_MAX];
};

struct fs_op_vfs_chmod {
    unsigned int minor;
    unsigned long long timestamp; // 操作时间戳
    unsigned long i_ino; // inode 号
    char path[PATH_MAX]; // 文件路径
    unsigned short mode; // 新 mode
};

struct fs_op_vfs_chown {
    unsigned int minor;
    unsigned long long timestamp;
    unsigned long i_ino;
    unsigned int uid;
    unsigned int gid;
};

struct netlink_response {
    int ret;
    enum msg_type type;
    enum op_type op_type; // type 为 MSG_OP_WATCH 时有效

    union {
        struct get_free_response get_free;
        struct fs_op_vfs_write op_write;
        struct fs_op_vfs_rename op_rename;
        struct fs_op_vfs_unlink op_unlink;
        struct fs_op_vfs_symlink op_symlink;
        struct fs_op_vfs_mkdir op_mkdir;
        struct fs_op_vfs_rmdir op_rmdir;
        struct fs_op_vfs_chmod op_chmod;
        struct fs_op_vfs_chown op_chown;
    };
};

#endif /* DATTOBD_H_ */
