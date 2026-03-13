// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Datto Inc.
 */

/*
 * 使用 kretprobe 跟踪 mount/umount 调用的入参与返回值，并据此维护块设备挂载状态。
 */

#include "kretprobe_hooking.h"

#define handle_bdev_mount_nowrite(dir_name, follow_flags, idx_out)                                 \
    handle_bdev_mount_event(dir_name, follow_flags, idx_out, 0)
#define handle_bdev_mounted_writable(dir_name, idx_out)                                            \
    handle_bdev_mount_event(dir_name, 0, idx_out, 1)

static struct probe_pool *probe_pool = NULL;

/**
 * probe_pool_init() - 初始化探测池的红黑树与自旋锁。
 * @p: 要初始化的 &struct probe_pool。
 */
void probe_pool_init(struct probe_pool *p)
{
    p->root = RB_ROOT;
    spin_lock_init(&p->lock);
}

/**
 * probe_pool_clear() - 清空探测池中所有节点并释放内存。
 * @p: 要清空的 &struct probe_pool。
 */
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

/**
 * insert_node() - 向红黑树插入键值对。
 * @root: 红黑树根。
 * @key: 键。
 * @data: 与键关联的数据指针。
 *
 * Return:
 * * 0 - 成功
 * * -EEXIST - 键已存在
 */
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
            return -EEXIST;
    }

    entry = kmalloc(sizeof(struct probe_entry), GFP_KERNEL);
    entry->key = key;
    entry->data = data;

    rb_link_node(&entry->node, parent, new);
    rb_insert_color(&entry->node, root);
    return 0;
}

/**
 * search_node() - 在红黑树中按键查找节点。
 * @root: 红黑树根。
 * @key: 要查找的键。
 *
 * Return: 找到则返回 &struct probe_entry，否则 NULL。
 */
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

/**
 * pop_node() - 从红黑树中移除键对应节点并返回其数据。
 * @root: 红黑树根。
 * @key: 键。
 *
 * Return: 若存在则返回该节点原 data，否则 NULL。
 */
void *pop_node(struct rb_root *root, unsigned long key)
{
    void *data = NULL;
    struct probe_entry *entry = search_node(root, key);
    if (entry) {
        rb_erase(&entry->node, root);
        data = entry->data;
        kfree(entry);
    }
    return data;
}

/**
 * probe_pool_insert() - 向探测池插入键值对（加锁）。
 * @p: 探测池。
 * @key: 键。
 * @data: 数据指针。
 *
 * Return: 0。
 */
int probe_pool_insert(struct probe_pool *p, unsigned long key, void *data)
{
    unsigned long flags;
    spin_lock_irqsave(&p->lock, flags);
    insert_node(&p->root, key, data);
    spin_unlock_irqrestore(&p->lock, flags);
    return 0;
}

/**
 * probe_pool_erase() - 从探测池中移除键对应项并返回其数据（加锁）。
 * @p: 探测池。
 * @key: 键。
 *
 * Return: 若存在则返回原 data，否则 NULL。
 */
void *probe_pool_erase(struct probe_pool *p, unsigned long key)
{
    unsigned long flags;
    void *data = NULL;
    spin_lock_irqsave(&p->lock, flags);
    data = pop_node(&p->root, key);
    spin_unlock_irqrestore(&p->lock, flags);
    return data;
}

/**
 * build_path() - 递归将 dentry 路径拼入 buffer。
 * @dentry: 目录项，从根向下拼接。
 * @buffer: 输出缓冲区。
 * @offset: 当前写入偏移，调用后更新。
 */
static void build_path(struct dentry *dentry, char *buffer, int *offset)
{
    if (!dentry || dentry == dentry->d_parent)
        return;

    build_path(dentry->d_parent, buffer, offset);

    *offset += snprintf(buffer + *offset, PATH_MAX - *offset, "/%s", dentry->d_name.name);
}

/**
 * get_absolute_path() - 根据 dentry 分配并返回绝对路径字符串。
 * @d: 目录项。
 *
 * Return: 成功为 kmalloc 分配的路径，调用方需 kfree；失败为 NULL。
 */
char *get_absolute_path(struct dentry *d)
{
    int offset = 0;
    char *buffer = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buffer)
        return NULL;

    build_path(d, buffer, &offset);
    return buffer;
}

/**
 * entry_mount_handler() - mount 系统调用入口的 kretprobe 处理函数。
 * @ri: kretprobe 实例。
 * @regs: 寄存器快照，用于取参数。
 *
 * 从寄存器中解析 mount 参数，分配 mount_params 并加入 probe_pool，供返回时使用。
 *
 * Return: 0。
 */
static int entry_mount_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int ret;
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
    {
        int sys_ret;

        strncpy(params->dev_name, (const char *)pt_regs_params(regs, 0), PATH_MAX);
        sys_ret = copy_from_user(params->dir_name, (const char __user *)pt_regs_params(regs, 1),
                                 PATH_MAX);
        if (sys_ret)
            goto error;
        strncpy(params->fs_type, (const char *)pt_regs_params(regs, 2), 64);
    }
    real_flags = pt_regs_params(regs, 3);
#else
    {
        int sys_ret;

        sys_ret = copy_from_user(params->dev_name, (char __user *)pt_regs_params(regs, 0),
                                PATH_MAX);
        if (sys_ret)
            goto error;
        sys_ret = copy_from_user(params->dir_name, (char __user *)pt_regs_params(regs, 1),
                                PATH_MAX);
        if (sys_ret)
            goto error;
        sys_ret = copy_from_user(params->fs_type, (char __user *)pt_regs_params(regs, 2), 64);
        if (sys_ret)
            goto error;
    }
    real_flags = pt_regs_params(regs, 3);
#endif

    if (strlen(params->dev_name) == 0)
        goto error;

    if ((real_flags & MS_MGC_MSK) == MS_MGC_VAL)
        real_flags &= ~MS_MGC_MSK;

    if ((real_flags & MS_RDONLY) && (real_flags & MS_REMOUNT)) {
        // 以只读方式重新挂载，对驱动而言等同于卸载
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

/**
 * ret_mount_handler() - mount 系统调用返回的 kretprobe 处理函数。
 * @ri: kretprobe 实例。
 * @regs: 寄存器快照，用于取返回值。
 *
 * 从 probe_pool 取出入口时保存的 mount_params，根据挂载结果调用
 * post_umount_check 或 handle_bdev_mounted_writable。
 *
 * Return: 0。
 */
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
        // 以只读方式重新挂载，对驱动而言等同于卸载
        post_umount_check(params->ret, sys_ret, params->idx, params->dir_name);
    } else {
        // 新的可读写挂载
        if (!sys_ret)
            handle_bdev_mounted_writable(params->dir_name, &params->idx);
    }
    kfree(params);

    return 0;
}

/**
 * entry_umount_handler() - umount 系统调用入口的 kretprobe 处理函数。
 * @ri: kretprobe 实例。
 * @regs: 寄存器快照，用于取参数。
 *
 * 从寄存器解析 umount 参数，分配 umount_params 并加入 probe_pool。
 *
 * Return: 0。
 */
static int entry_umount_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int ret;
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

    // 若存在魔数则去掉
    if ((real_flags & MS_MGC_MSK) == MS_MGC_VAL)
        real_flags &= ~MS_MGC_MSK;

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
    {
        int sys_ret = copy_from_user(params->dir_name, (char __user *)pt_regs_params(regs, 0),
                                    PATH_MAX);
        if (sys_ret)
            goto error;
    }
    real_flags = pt_regs_params(regs, 1);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    {
        int sys_ret = copy_from_user(params->dir_name, (char __user *)pt_regs_params(regs, 0),
                                    PATH_MAX);
        if (sys_ret)
            goto error;
    }
    real_flags = pt_regs_params(regs, 1);
#else
#ifdef HAVE_SYS_OLDUMOUNT
    {
        int sys_ret = copy_from_user(params->dir_name, (char __user *)pt_regs_params(regs, 0),
                                    PATH_MAX);
        if (sys_ret)
            goto error;
    }
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

/**
 * ret_umount_handler() - umount 系统调用返回的 kretprobe 处理函数。
 * @ri: kretprobe 实例。
 * @regs: 寄存器快照，用于取返回值。
 *
 * 从 probe_pool 取出入口时保存的 umount_params，调用 post_umount_check。
 *
 * Return: 0。
 */
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
 * register_hook() - 注册并启用单个钩子。
 * @hook: 要安装的钩子。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
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
 * unregister_hook() - 禁用并注销单个钩子。
 * @hook: 要移除的钩子。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
static int unregister_hook(struct kretprobe *hook)
{
    int ret = 0;
    unregister_kretprobe(hook);
    return ret;
}

/**
 * register_kretprobe_hooks() - 注册并启用所有 kretprobe 钩子（mount/umount）。
 *
 * 分配全局 probe_pool 并依次注册 kretprobe_hooks 中的钩子。
 *
 * Return:
 * * 0 - 成功
 * * !0 - 表示错误的 errno
 */
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

/**
 * unregister_kretprobe_hooks() - 禁用并注销所有 kretprobe 钩子，清空探测池。
 *
 * Return: 0。
 */
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