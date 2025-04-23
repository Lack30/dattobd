#ifndef __KERNEL_HOOKING_H
#define __KERNEL_HOOKING_H

#if defined(CONFIG_HAVE_DYNAMIC_FTRACE_WITH_REGS) || defined(CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS)
#include "ftrace_hooking.h"
#else
#include "kretprobe_hooking.h"
#endif

#if defined(CONFIG_HAVE_DYNAMIC_FTRACE_WITH_REGS) || defined(CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS)
#define REGISTER_HOOKS register_ftrace_hooks
#define UNREGISTER_HOOKS unregister_ftrace_hooks
#else
#define REGISTER_HOOKS register_kretprobe_hooks
#define UNREGISTER_HOOKS unregister_kretprobe_hooks
#endif

#endif