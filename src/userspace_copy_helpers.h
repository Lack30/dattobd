// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#ifndef USERSPACE_COPY_HELPERS_H_
#define USERSPACE_COPY_HELPERS_H_

#include "dattobd.h"
#include "includes.h"

int copy_string_from_user(const char __user *data, char **out_ptr);

int get_setup_params(const struct setup_params __user *in, unsigned int *minor, char **bdev_name,
					 char **cow_path, unsigned long *fallocated_space, unsigned long *cache_size);

int get_destroy_params(const struct destroy_params __user *in, unsigned int *minor);

int get_transition_inc_params(const struct transition_inc_params __user *in, unsigned int *minor);

int get_reload_params(const struct reload_params __user *in, unsigned int *minor, char **bdev_name,
					  char **cow_path, unsigned long *cache_size);

int get_transition_snap_params(const struct transition_snap_params __user *in, unsigned int *minor,
							   char **cow_path, unsigned long *fallocated_space);

int get_reconfigure_params(const struct reconfigure_params __user *in, unsigned int *minor,
						   unsigned long *cache_size);

int get_expand_cow_file_params(const struct expand_cow_file_params __user *in, unsigned int *minor,
							   uint64_t *size);

int get_reconfigure_auto_expand_params(const struct reconfigure_auto_expand_params __user *in,
									   unsigned int *minor, uint64_t *step_size,
									   uint64_t *reserved_space);

int user_path_at(int dfd, const char __user *name, unsigned flags, struct path *path);

#endif /* USERSPACE_COPY_HELPERS_H_ */
