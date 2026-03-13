/*
 * 声明 Netlink 控制通道的初始化、销毁、发送接口及全局互斥锁。
 */

#ifndef NETLINK_HANDLERS_H_
#define NETLINK_HANDLERS_H_

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/slab.h>
#include <net/sock.h>

#include "dattobd.h"

extern struct mutex netlink_mutex;

int setup_netlink_handler(unsigned int unit);

void destroy_netlink_handler(void);

int dattobd_netlink_sendto(struct netlink_response *resp, int pid);

#endif