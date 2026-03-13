// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Datto Inc.
 */

/*
 * 从 block change stream 字符设备读取记录并顺序写入本地日志文件。
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dattobd.h"

#define BCS_READ_BUFFER_SIZE (512 * 1024)

static void print_help(const char *progname, int status)
{
    fprintf(stderr, "Usage: %s <minor> <output file>\n", progname);
    exit(status);
}

static int parse_minor(const char *value, unsigned int *minor)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno || !end || *end || parsed > UINT32_MAX)
        return -1;

    *minor = (unsigned int)parsed;
    return 0;
}

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;

    while (len) {
        ssize_t written = write(fd, p, len);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        p += written;
        len -= written;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret = 1;
    int dev_fd = -1;
    int out_fd = -1;
    int poll_ret;
    unsigned int minor;
    ssize_t bytes;
    char dev_path[PATH_MAX];
    uint8_t *buffer = NULL;
    struct pollfd pfd;
    struct bcslog_file_header header;

    if (argc != 3)
        print_help(argv[0], EINVAL);

    if (parse_minor(argv[1], &minor)) {
        fprintf(stderr, "invalid minor: %s\n", argv[1]);
        return 1;
    }

    snprintf(dev_path, sizeof(dev_path), "/dev/dattobcs%u", minor);

    dev_fd = open(dev_path, O_RDONLY);
    if (dev_fd < 0) {
        perror("error opening block change stream device");
        goto out;
    }

    out_fd = open(argv[2], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (out_fd < 0) {
        perror("error opening output file");
        goto out;
    }

    memset(&header, 0, sizeof(header));
    header.magic = BCSLOG_MAGIC;
    header.version = BCSLOG_VERSION;
    header.minor = minor;
    if (write_all(out_fd, &header, sizeof(header))) {
        perror("error writing bcslog header");
        goto out;
    }

    buffer = malloc(BCS_READ_BUFFER_SIZE);
    if (!buffer) {
        perror("error allocating read buffer");
        goto out;
    }

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = dev_fd;
    pfd.events = POLLIN | POLLERR;

    for (;;) {
        poll_ret = poll(&pfd, 1, -1);
        if (poll_ret < 0) {
            if (errno == EINTR)
                continue;
            perror("error polling block change stream device");
            goto out;
        }

        if (pfd.revents & POLLERR) {
            fprintf(stderr, "block change stream device reported an error\n");
            goto out;
        }

        if (!(pfd.revents & POLLIN))
            continue;

        bytes = read(dev_fd, buffer, BCS_READ_BUFFER_SIZE);
        if (bytes < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ENOSPC) {
                fprintf(stderr, "read buffer too small for next block change stream record\n");
                goto out;
            }
            perror("error reading block change stream device");
            goto out;
        }

        if (bytes == 0)
            continue;

        if (write_all(out_fd, buffer, bytes)) {
            perror("error writing block change stream log");
            goto out;
        }

        ret = 0;
    }

out:
    if (buffer)
        free(buffer);
    if (out_fd >= 0)
        close(out_fd);
    if (dev_fd >= 0)
        close(dev_fd);

    return ret;
}
