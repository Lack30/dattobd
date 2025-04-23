// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

#include "kretprobe_hooking.h"
#include "kernel-config.h"

#define handle_bdev_mount_nowrite(dir_name, follow_flags, idx_out)                                 \
	handle_bdev_mount_event(dir_name, follow_flags, idx_out, 0)
#define handle_bdev_mounted_writable(dir_name, idx_out)                                            \
	handle_bdev_mount_event(dir_name, 0, idx_out, 1)

static struct probe_pool *probe_pool = NULL;

void probe_pool_init(struct probe_pool *p)
{
	p->root = RB_ROOT;
	spin_lock_init(&p->lock);
}

void probe_pool_clear(struct probe_pool *p)
{
	unsigned long flags;
	struct rb_node *node;
	spin_lock_irqsave(&p->lock, flags);
	while ((node = rb_first(&p->root))) {
		struct probe_entry *entry = rb_entry(node, struct probe_entry, node);
		rb_erase(node, &p->root);
		kfree(entry);
	}
	spin_unlock_irqrestore(&p->lock, flags);
}

int insert_node(struct rb_root *root, unsigned long key, void *data)
{
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;
	struct probe_entry *entry;

	// 查找插入位置
	while (*new) {
		struct probe_entry *cur = rb_entry(*new, struct probe_entry, node);
		parent = *new;
		if (key < cur->key)
			new = &(*new)->rb_left;
		else if (key > cur->key)
			new = &(*new)->rb_right;
		else
			return -EEXIST; // 键值已存在
	}

	// 分配新节点
	entry = kmalloc(sizeof(struct probe_entry), GFP_KERNEL);
	entry->key = key;
	entry->data = data;

	// 链接节点并调整颜色
	rb_link_node(&entry->node, parent, new);
	rb_insert_color(&entry->node, root);
	return 0;
}

struct probe_entry *search_node(struct rb_root *root, unsigned long key)
{
	struct rb_node *n = root->rb_node;
	while (n) {
		struct probe_entry *cur = rb_entry(n, struct probe_entry, node);
		if (key < cur->key)
			n = n->rb_left;
		else if (key > cur->key)
			n = n->rb_right;
		else
			return cur;
	}
	return NULL;
}

void *pop_node(struct rb_root *root, unsigned long key)
{
	void *data = NULL;
	struct probe_entry *entry = search_node(root, key);
	if (entry) {
		rb_erase(&entry->node, root); // 从树中移除
		data = entry->data;
		kfree(entry); // 释放节点内存
	}
	return data;
}

int probe_pool_insert(struct probe_pool *p, unsigned long key, void *data)
{
	unsigned long flags;
	spin_lock_irqsave(&p->lock, flags);
	insert_node(&p->root, key, data);
	spin_unlock_irqrestore(&p->lock, flags);
	return 0;
}

void *probe_pool_erase(struct probe_pool *p, unsigned long key)
{
	unsigned long flags;
	void *data = NULL;
	spin_lock_irqsave(&p->lock, flags);
	data = pop_node(&p->root, key);
	spin_unlock_irqrestore(&p->lock, flags);
	return data;
}

static void build_path(struct dentry *dentry, char *buffer, int *offset)
{
	if (!dentry || dentry == dentry->d_parent)
		return;

	build_path(dentry->d_parent, buffer, offset);

	*offset += snprintf(buffer + *offset, PATH_MAX - *offset, "/%s", dentry->d_name.name);
}

char *get_absolute_path(struct dentry *d)
{
	int offset = 0;
	char *buffer = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buffer)
		return NULL;

	build_path(d, buffer, &offset);
	return buffer;
}

static int entry_mount_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int ret;
	int sys_ret;
	unsigned int idx = 0;
	unsigned long real_flags;
	struct mount_params *params;
	unsigned long ptr = (unsigned long)ri;

	params = kmalloc(sizeof(struct mount_params), GFP_KERNEL);
	if (!params)
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	strncpy(params->dev_name, (const char *)pt_regs_params(regs, 0), PATH_MAX);
	strncpy(params->dir_name, get_absolute_path(((struct path *)pt_regs_params(regs, 1))->dentry),
			PATH_MAX);
	strncpy(params->fs_type, (const char *)pt_regs_params(regs, 2), 64);
	real_flags = pt_regs_params(regs, 3);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
	strncpy(params->dev_name, (const char *)pt_regs_params(regs, 0), PATH_MAX);
	sys_ret = copy_from_user(params->dir_name, (const char __user *)pt_regs_params(regs, 1),
							 PATH_MAX);
	if (sys_ret)
		goto error;
	strncpy(params->fs_type, (const char *)pt_regs_params(regs, 2), 64);
	real_flags = pt_regs_params(regs, 3);
#else
	sys_ret = copy_from_user(params->dev_name, (char __user *)pt_regs_params(regs, 0), PATH_MAX);
	if (sys_ret)
		goto error;
	sys_ret = copy_from_user(params->dir_name, (char __user *)pt_regs_params(regs, 1), PATH_MAX);
	if (sys_ret)
		goto error;
	sys_ret = copy_from_user(params->fs_type, (char __user *)pt_regs_params(regs, 2), 64);
	if (sys_ret)
		goto error;
	real_flags = pt_regs_params(regs, 3);
#endif

	if (strlen(params->dev_name) == 0)
		goto error;

	if ((real_flags & MS_MGC_MSK) == MS_MGC_VAL)
		real_flags &= ~MS_MGC_MSK;

	if ((real_flags & MS_RDONLY) && (real_flags & MS_REMOUNT)) {
		// we are remounting read-only, same as umounting as far as the
		// driver is concerned
		ret = handle_bdev_mount_nowrite(params->dir_name, 0, &idx);
		params->ret = ret;
	}
	params->flags = real_flags;

	LOG_DEBUG("mount %s to %s, type=%s flags=%lx", params->dev_name, params->dir_name,
			  params->fs_type, real_flags);
	probe_pool_insert(probe_pool, ptr, (void *)params);

	return 0;

error:
	kfree(params);
	return 0;
}

static int ret_mount_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int sys_ret;
	unsigned long ptr = 0;
	unsigned long real_flags = 0;
	struct mount_params *params = NULL;

	sys_ret = (int)pt_regs_returns(regs);

	if (!regs)
		return 0;
	else
		ptr = (unsigned long)ri;

	params = (struct mount_params *)probe_pool_erase(probe_pool, ptr);
	if (!params)
		return 0;

	real_flags = params->flags;
	if ((real_flags & MS_RDONLY) && (real_flags & MS_REMOUNT)) {
		// we are remounting read-only, same as umounting as far as the
		// driver is concerned
		post_umount_check(params->ret, sys_ret, params->idx, params->dir_name);
	} else {
		// new read-write mount
		if (!sys_ret)
			handle_bdev_mounted_writable(params->dir_name, &params->idx);
	}
	kfree(params);

	return 0;
}

static int entry_umount_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int ret;
	int sys_ret;
	struct umount_params *params;
	unsigned int idx = 0;
	unsigned int real_flags;
	unsigned long ptr = (unsigned long)ri;

	params = kmalloc(sizeof(struct umount_params), GFP_KERNEL);
	if (!params)
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	strncpy(params->dir_name, get_absolute_path(((struct path *)pt_regs_params(regs, 0))->dentry),
			PATH_MAX);
	real_flags = pt_regs_params(regs, 1);

	// get rid of the magic value if its present
	if ((real_flags & MS_MGC_MSK) == MS_MGC_VAL)
		real_flags &= ~MS_MGC_MSK;

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
	sys_ret = copy_from_user(params->dir_name, (char __user *)pt_regs_params(regs, 0), PATH_MAX);
	if (sys_ret)
		goto error;
	real_flags = pt_regs_params(regs, 1);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	sys_ret = copy_from_user(params->dir_name, (char __user *)pt_regs_params(regs, 0), PATH_MAX);
	if (sys_ret)
		goto error;
	real_flags = pt_regs_params(regs, 1);
#else
#ifdef HAVE_SYS_OLDUMOUNT
	sys_ret = copy_from_user(params->dir_name, (char __user *)pt_regs_params(regs, 0), PATH_MAX);
	if (sys_ret)
		goto error;
#endif
#endif

	if (strlen(params->dir_name) == 0)
		goto error;

	ret = handle_bdev_mount_nowrite(params->dir_name, real_flags, &idx);
	params->ret = ret;
	params->idx = idx;

	LOG_DEBUG("umount %s flags=%x", params->dir_name, real_flags);
	probe_pool_insert(probe_pool, ptr, (void *)params);

	return 0;

error:
	kfree(params);
	return 0;
}

static int ret_umount_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int sys_ret;
	unsigned long ptr = 0;
	int real_flags = 0;
	struct umount_params *params = NULL;

	sys_ret = (int)pt_regs_returns(regs);

	if (!regs)
		return 0;
	else
		ptr = (unsigned long)ri;

	params = (struct umount_params *)probe_pool_erase(probe_pool, ptr);
	if (!params)
		return 0;

	real_flags = params->flags;
	post_umount_check(params->ret, sys_ret, params->idx, params->dir_name);

	kfree(params);

	return 0;
}

static struct kretprobe kretprobe_hooks[] = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	KRETPROBE("path_mount", entry_mount_handler, ret_mount_handler),
	KRETPROBE("path_umount", entry_umount_handler, ret_umount_handler),
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
	KRETPROBE("do_mount", entry_mount_handler, ret_mount_handler),
	KRETPROBE("ksys_umount", entry_umount_handler, ret_umount_handler),
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	KRETPROBE("ksys_mount", entry_mount_handler, ret_mount_handler),
	KRETPROBE("ksys_umount", entry_umount_handler, ret_umount_handler),
#else
	KRETPROBE("sys_mount", entry_mount_handler, ret_mount_handler),
	KRETPROBE("sys_umount", entry_umount_handler, ret_umount_handler),
#ifdef HAVE_SYS_OLDUMOUNT
	KRETPROBE("sys_oldumount", entry_umount_handler, ret_umount_handler),
#endif //HAVE_SYS_OLDUMOUNT
#endif //LINUX_VERSION_CODE
};

/**
 * register_hook() - registers and enables a single hook
 * @hook: a hook to install
 * 
 * Return:
 * 0 - success
 * !0 - an errno indicating the error
 */
static int register_hook(struct kretprobe *hook)
{
	int ret = 0;

	ret = register_kretprobe(hook);
	if (ret) {
		LOG_ERROR(ret, "register_kretprobe failed, returned\n");
		return -EINVAL;
	}

	LOG_DEBUG("registered kretprobe hook for %s", hook->kp.symbol_name);

	return ret;
}

/**
 * unregister_hook() - disable and unregister a single hook
 * @hook: a hook to remove
 * 
 * Return:
 * 0 - success
 * !0 - an errno indicating the error
 */
static int unregister_hook(struct kretprobe *hook)
{
	int ret = 0;
	unregister_kretprobe(hook);
	return ret;
}

int register_kretprobe_hooks(void)
{
	int ret = 0;
	int i;
	int count = ARRAY_SIZE(kretprobe_hooks);

	probe_pool = kmalloc(sizeof(struct probe_pool), GFP_KERNEL);
	probe_pool_init(probe_pool);

	for (i = 0; i < count; i++) {
		ret = register_hook(&kretprobe_hooks[i]);
		if (ret)
			goto error;
	}

	return 0;
error:
	while (i != 0) {
		unregister_hook(&kretprobe_hooks[--i]);
	}
	return ret;
}

int unregister_kretprobe_hooks(void)
{
	int ret = 0;
	int i;
	int count = ARRAY_SIZE(kretprobe_hooks);

	for (i = 0; i < count; i++) {
		unregister_hook(&kretprobe_hooks[i]);
	}

	probe_pool_clear(probe_pool);

	return ret;
}