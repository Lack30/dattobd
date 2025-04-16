// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2015 Datto Inc.
 */

#define _FILE_OFFSET_BITS 64 // 启用 64 位文件操作支持
#define __USE_LARGEFILE64 // 使用大文件支持的库函数

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "libdattobd.h" // 包含 dattobd 库的头文件

#define INDEX_BUFFER_SIZE 8192 // 定义索引缓冲区大小

// 定义一个宏，用于返回两个值中的较小值
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

typedef unsigned long long sector_t; // 定义 sector_t 类型为无符号长长整型

// 打印帮助信息并退出程序
static void print_help(char *progname, int status)
{
	fprintf(stderr, "Usage: %s <snapshot device> <cow file> <image file>\n", progname);
	exit(status);
}

// 从快照文件中读取一个块并写入到目标镜像文件
static int copy_block(FILE *snap, FILE *img, sector_t block)
{
	char buf[COW_BLOCK_SIZE]; // 用于存储块数据的缓冲区
	int ret;
	size_t bytes;

	// 从快照文件中读取一个块
	bytes = pread(fileno(snap), buf, COW_BLOCK_SIZE, block * COW_BLOCK_SIZE);
	if (bytes != COW_BLOCK_SIZE) {
		ret = errno; // 保存错误代码
		errno = 0;
		fprintf(stderr, "error reading data block from snapshot\n");
		goto error;
	}

	// 将块数据写入目标镜像文件
	bytes = pwrite(fileno(img), buf, COW_BLOCK_SIZE, block * COW_BLOCK_SIZE);
	if (bytes != COW_BLOCK_SIZE) {
		ret = errno; // 保存错误代码
		errno = 0;
		fprintf(stderr, "error writing data block to output image\n");
		goto error;
	}

	return 0;

error:
	fprintf(stderr, "error copying sector to output image\n");
	return ret;
}

// 验证 COW 文件和快照设备是否匹配
static int verify_files(FILE *cow, unsigned minor)
{
	int ret;
	size_t bytes;
	struct cow_header ch; // COW 文件头结构
	struct dattobd_info *info = NULL;

	// 为 dattobd 信息分配内存
	info = malloc(sizeof(struct dattobd_info));
	if (!info) {
		ret = ENOMEM;
		errno = 0;
		fprintf(stderr, "error allocating memory for dattobd info\n");
		goto error;
	}

	// 从 dattobd 驱动程序读取信息
	ret = dattobd_info(minor, info);
	if (ret) {
		ret = errno;
		errno = 0;
		fprintf(stderr, "error reading dattobd info from driver\n");
		goto error;
	}

	// 从 COW 文件中读取文件头
	bytes = pread(fileno(cow), &ch, sizeof(struct cow_header), 0);
	if (bytes != sizeof(struct cow_header)) {
		ret = errno;
		errno = 0;
		fprintf(stderr, "error reading cow header\n");
		goto error;
	}

	// 检查 COW 文件的魔数是否正确
	if (ch.magic != COW_MAGIC) {
		ret = EINVAL;
		fprintf(stderr, "invalid magic number from cow file\n");
		goto error;
	}

	// 检查 UUID 是否匹配
	if (memcmp(ch.uuid, info->uuid, COW_UUID_SIZE) != 0) {
		ret = EINVAL;
		fprintf(stderr, "cow file uuid does not match snapshot\n");
		goto error;
	}

	// 检查序列号是否正确
	if (ch.seqid != info->seqid - 1) {
		ret = EINVAL;
		fprintf(stderr, "snapshot provided does not immediately follow the snapshot that created the cow file\n");
		goto error;
	}

	free(info); // 释放分配的内存

	return 0;

error:
	if (info)
		free(info);
	return ret;
}

// 主函数
int main(int argc, char **argv)
{
	int ret;
	unsigned minor;
	size_t snap_size, bytes, blocks_to_read;
	sector_t total_chunks, total_blocks, i, j, blocks_done = 0, count = 0, err_count = 0;
	FILE *cow = NULL, *snap = NULL, *img = NULL;
	uint64_t *mappings = NULL;
	char *snap_path;
	char snap_path_buf[PATH_MAX];

	// 检查参数数量是否正确
	if (argc != 4)
		print_help(argv[0], EINVAL);

	// 打开快照文件
	snap = fopen(argv[1], "r");
	if (!snap) {
		ret = errno;
		errno = 0;
		fprintf(stderr, "error opening snapshot\n");
		goto error;
	}

	// 打开 COW 文件
	cow = fopen(argv[2], "r");
	if (!cow) {
		ret = errno;
		errno = 0;
		fprintf(stderr, "error opening cow file\n");
		goto error;
	}

	// 打开目标镜像文件
	img = fopen(argv[3], "r+");
	if (!img) {
		ret = errno;
		errno = 0;
		fprintf(stderr, "error opening image\n");
		goto error;
	}

	// 获取快照文件的完整路径
	snap_path = realpath(argv[1], snap_path_buf);
	if (!snap_path) {
		ret = errno;
		errno = 0;
		fprintf(stderr, "error determining full path of snapshot\n");
		goto error;
	}

	// 获取快照设备的次设备号
	ret = sscanf(snap_path, "/dev/datto%u", &minor);
	if (ret != 1) {
		ret = errno;
		errno = 0;
		fprintf(stderr, "snapshot does not appear to be a dattobd snapshot device\n");
		goto error;
	}

	// 验证输入文件是否匹配
	ret = verify_files(cow, minor);
	if (ret)
		goto error;

	// 获取快照文件的大小并计算块和块组的数量
	fseeko(snap, 0, SEEK_END);
	snap_size = ftello(snap);
	total_blocks = (snap_size + COW_BLOCK_SIZE - 1) / COW_BLOCK_SIZE;
	total_chunks = (total_blocks + INDEX_BUFFER_SIZE - 1) / INDEX_BUFFER_SIZE;
	rewind(snap);

	printf("snapshot is %llu blocks large\n", total_blocks);

	// 分配映射数组
	mappings = malloc(INDEX_BUFFER_SIZE * sizeof(uint64_t));
	if (!mappings) {
		ret = ENOMEM;
		fprintf(stderr, "error allocating mappings\n");
		goto error;
	}

	// 开始合并块
	printf("copying blocks\n");
	for (i = 0; i < total_chunks; i++) {
		// 从 COW 文件中读取一组映射
		blocks_to_read = MIN(INDEX_BUFFER_SIZE, total_blocks - blocks_done);

		bytes = pread(fileno(cow), mappings, blocks_to_read * sizeof(uint64_t),
					  COW_HEADER_SIZE + (INDEX_BUFFER_SIZE * sizeof(uint64_t) * i));
		if (bytes != blocks_to_read * sizeof(uint64_t)) {
			ret = errno;
			errno = 0;
			fprintf(stderr, "error reading mappings into memory: bytes %ld, expect %ld(block=%ld, fact=%ld)\n", bytes,
					blocks_to_read * sizeof(uint64_t), blocks_to_read, sizeof(uint64_t));
			goto error;
		}

		// 复制映射中标记的块
		for (j = 0; j < blocks_to_read; j++) {
			if (!mappings[j])
				continue;

			ret = copy_block(snap, img, (INDEX_BUFFER_SIZE * i) + j);
			if (ret)
				err_count++;

			count++;
		}

		blocks_done += blocks_to_read;
	}

	// 打印合并结果
	printf("copying complete: %llu blocks changed, %llu errors\n", count, err_count);

	free(mappings);
	fclose(cow);
	fclose(snap);
	fclose(img);

	return 0;

error:
	if (mappings)
		free(mappings);
	if (cow)
		fclose(cow);
	if (snap)
		fclose(snap);
	if (img)
		fclose(img);

	return ret;
}
