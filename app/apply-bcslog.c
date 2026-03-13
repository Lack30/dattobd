// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

/*
 * 将 block change stream 日志中的 block payload 记录回放到目标镜像文件。
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dattobd.h"

static void print_help(const char *progname, int status)
{
    fprintf(stderr, "Usage: %s <bcslog file> <image file>\n", progname);
    exit(status);
}

static int read_exact(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;

    while (len) {
        ssize_t bytes = read(fd, p, len);
        if (bytes < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (bytes == 0)
            return 1;

        p += bytes;
        len -= bytes;
    }

    return 0;
}

static int read_record_header(int fd, struct bcs_record_header *hdr)
{
    int ret = read_exact(fd, hdr, sizeof(*hdr));

    if (ret)
        return ret;
    if (hdr->length < sizeof(*hdr)) {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static int skip_bytes(int fd, size_t len)
{
    uint8_t buf[4096];

    while (len) {
        size_t chunk = len < sizeof(buf) ? len : sizeof(buf);
        int ret = read_exact(fd, buf, chunk);
        if (ret)
            return ret;
        len -= chunk;
    }

    return 0;
}

static int apply_block_record(int img_fd, const struct bcs_record_block *record)
{
    off_t offset;
    ssize_t bytes;

    if (record->data_len != COW_BLOCK_SIZE) {
        errno = EINVAL;
        return -1;
    }

    offset = (off_t)record->block_no * COW_BLOCK_SIZE;
    bytes = pwrite(img_fd, record->data, COW_BLOCK_SIZE, offset);
    if (bytes != COW_BLOCK_SIZE)
        return -1;

    return 0;
}

int main(int argc, char **argv)
{
    int ret = 1;
    int log_fd = -1;
    int img_fd = -1;
    uint64_t applied_blocks = 0;
    uint64_t skipped_ranges = 0;
    struct bcslog_file_header file_hdr;

    if (argc != 3)
        print_help(argv[0], EINVAL);

    log_fd = open(argv[1], O_RDONLY);
    if (log_fd < 0) {
        perror("error opening bcslog file");
        goto out;
    }

    img_fd = open(argv[2], O_CREAT | O_RDWR, 0644);
    if (img_fd < 0) {
        perror("error opening image file");
        goto out;
    }

    ret = read_exact(log_fd, &file_hdr, sizeof(file_hdr));
    if (ret) {
        if (ret > 0)
            fprintf(stderr, "unexpected end of file reading bcslog header\n");
        else
            perror("error reading bcslog header");
        goto out;
    }

    if (file_hdr.magic != BCSLOG_MAGIC || file_hdr.version != BCSLOG_VERSION) {
        fprintf(stderr, "invalid bcslog header\n");
        goto out;
    }

    for (;;) {
        struct bcs_record_header hdr;

        ret = read_record_header(log_fd, &hdr);
        if (ret > 0) {
            ret = 0;
            break;
        }
        if (ret < 0) {
            perror("error reading bcslog record header");
            goto out;
        }

        if (hdr.type == BCS_RECORD_BLOCK) {
            struct bcs_record_block record;

            if (hdr.length != sizeof(record)) {
                fprintf(stderr, "invalid block record length: %u\n", hdr.length);
                goto out;
            }

            memcpy(&record.hdr, &hdr, sizeof(hdr));
            ret = read_exact(log_fd, ((uint8_t *)&record) + sizeof(hdr),
                             sizeof(record) - sizeof(hdr));
            if (ret) {
                if (ret > 0)
                    fprintf(stderr, "unexpected end of file reading block record\n");
                else
                    perror("error reading block record");
                goto out;
            }

            if (apply_block_record(img_fd, &record)) {
                perror("error applying block record");
                goto out;
            }

            applied_blocks++;
        } else if (hdr.type == BCS_RECORD_RANGE) {
            ret = skip_bytes(log_fd, hdr.length - sizeof(hdr));
            if (ret) {
                if (ret > 0)
                    fprintf(stderr, "unexpected end of file skipping range record\n");
                else
                    perror("error skipping range record");
                goto out;
            }
            skipped_ranges++;
        } else {
            fprintf(stderr, "unknown bcslog record type: %u\n", hdr.type);
            goto out;
        }
    }

    if (fsync(img_fd)) {
        perror("error syncing image file");
        goto out;
    }

    printf("applied %" PRIu64 " block records, skipped %" PRIu64 " range records\n", applied_blocks,
           skipped_ranges);
    ret = 0;

out:
    if (img_fd >= 0)
        close(img_fd);
    if (log_fd >= 0)
        close(log_fd);

    return ret;
}
