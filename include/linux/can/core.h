/*
 * linux/can/core.h
 *
 * Protoypes and definitions for CAN protocol modules using the PF_CAN core
 *
 * Authors: Oliver Hartkopp <oliver.hartkopp@volkswagen.de>
 *          Urs Thuermann   <urs.thuermann@volkswagen.de>
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 */

#ifndef CAN_CORE_H
#define CAN_CORE_H

#include <linux/can.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/rtnetlink.h>

#define CAN_VERSION "20120528"

/* increment this number each time you change some user-space interface */
#define CAN_ABI_VERSION "9"

#define CAN_VERSION_STRING "rev " CAN_VERSION " abi " CAN_ABI_VERSION

#define DNAME(dev) ((dev) ? (dev)->name : "any")

/**
 * struct can_proto - CAN protocol structure
 * @type:       type argument in socket() syscall, e.g. SOCK_DGRAM.
 * @protocol:   protocol number in socket() syscall.
 * @ops:        pointer to struct proto_ops for sock->ops.
 * @prot:       pointer to struct proto structure.
 */
struct can_proto {
	int type;
	int protocol;
	const struct proto_ops *ops;
	struct proto *prot;
	const struct rtnl_af_ops *rtnl_link_ops;
	/*
	 * hooks for rtnl hooks
	 * for the *dump* functions, cb->args[0] is reserved
	 * for use by af_can.c, so keep your fingers off.
	 */
	rtnl_doit_func rtnl_new_addr;
	rtnl_doit_func rtnl_del_addr;
	rtnl_dumpit_func rtnl_dump_addr;
};

/*
 * this is quite a dirty hack:
 * reuse the second byte of a rtnetlink msg
 * to indicate the precise protocol.
 * The major problem is that is may conflict
 * with the prefixlen in struct ifaddrmsg.
 */
struct rtgencanmsg {
	unsigned char rtgen_family;
	unsigned char can_protocol;
};

/*
 * required_size
 * macro to find the minimum size of a struct
 * that includes a requested member
 */
#define required_size(member, struct_type) \
	(offsetof(typeof(struct_type), member) + \
	 sizeof(((typeof(struct_type) *)(0))->member))

/* function prototypes for the CAN networklayer core (af_can.c) */

extern int  can_proto_register(const struct can_proto *cp);
extern void can_proto_unregister(const struct can_proto *cp);

extern int  can_rx_register(struct net_device *dev, canid_t can_id,
			    canid_t mask,
			    void (*func)(struct sk_buff *, void *),
			    void *data, char *ident);

extern void can_rx_unregister(struct net_device *dev, canid_t can_id,
			      canid_t mask,
			      void (*func)(struct sk_buff *, void *),
			      void *data);

extern int can_send(struct sk_buff *skb, int loop);
extern int can_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);

#endif /* CAN_CORE_H */
