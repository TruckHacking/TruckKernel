/*
 * Copyright (c) 2010-2011 EIA Electronics
 *
 * Authors:
 * Kurt Van Dijck <kurt.van.dijck@eia.be>
 * Pieter Beyens <pieter.beyens@eia.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 */

/*
 * Core of can-j1939 that links j1939 to CAN.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/list.h>
#include <linux/if_arp.h>
#include <net/tcp_states.h>

#include <linux/can.h>
#include <linux/can/core.h>
#include "j1939-priv.h"

MODULE_DESCRIPTION("PF_CAN SAE J1939");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("EIA Electronics (Kurt Van Dijck & Pieter Beyens)");

static struct {
	struct notifier_block notifier;
} s;

/* LOWLEVEL CAN interface */

/* CAN_HDR: #bytes before can_frame data part */
#define CAN_HDR	(offsetof(struct can_frame, data))
/* CAN_FTR: #bytes beyond data part */
#define CAN_FTR	(sizeof(struct can_frame)-CAN_HDR-\
		sizeof(((struct can_frame *)0)->data))

static void j1939_recv_ecu_flags(struct sk_buff *skb, void *data)
{
	struct j1939_segment *jseg = data;
	struct j1939_sk_buff_cb *cb = (void *)skb->cb;
	struct addr_ent *paddr;

	if (!jseg)
		return;
	write_lock_bh(&jseg->lock);
	if (j1939_address_is_unicast(cb->src.addr)) {
		paddr = &jseg->ents[cb->src.addr];
		paddr->rxtime = ktime_get();
		if (0x0ee00 == cb->pgn) {
			/* do not touch many things for Address claims */
		} else if (paddr->ecu) {
			paddr->ecu->rxtime = paddr->rxtime;
			cb->src.flags = paddr->ecu->flags;
		} else {
			if (!paddr->flags)
				paddr->flags |= ECUFLAG_REMOTE;
			cb->src.flags = paddr->flags;
		}
	}

	if (j1939_address_is_unicast(cb->dst.addr)) {
		paddr = &jseg->ents[cb->dst.addr];
		if (paddr->ecu)
			cb->dst.flags = paddr->ecu->flags;
		else
			cb->dst.flags = paddr->flags ?: ECUFLAG_REMOTE;
	}
	write_unlock_bh(&jseg->lock);
}

/* lowest layer */
static void j1939_can_recv(struct sk_buff *skb, void *data)
{
	int orig_len;
	struct j1939_sk_buff_cb *sk_addr;
	struct can_frame *msg;
	uint8_t saved_cb[sizeof(skb->cb)];

	BUILD_BUG_ON(sizeof(*sk_addr) > sizeof(skb->cb));
	/*
	 * get a pointer to the header of the skb
	 * the skb payload (pointer) is moved, so that the next skb_data
	 * returns the actual payload
	 */
	msg = (void *)skb->data;
	orig_len = skb->len;
	skb_pull(skb, CAN_HDR);
	/* fix length, set to dlc, with 8 maximum */
	skb_trim(skb, min_t(uint8_t, msg->can_dlc, 8));

	/* set addr */
	sk_addr = (struct j1939_sk_buff_cb *)skb->cb;
	memcpy(saved_cb, sk_addr, sizeof(saved_cb));
	memset(sk_addr, 0, sizeof(*sk_addr));
	if (skb->dev)
		sk_addr->ifindex = skb->dev->ifindex;
	sk_addr->priority = (msg->can_id & 0x1c000000) >> 26;
	sk_addr->src.addr = msg->can_id & 0xff;
	sk_addr->pgn = (msg->can_id & 0x3ffff00) >> 8;
	if (pgn_is_pdu1(sk_addr->pgn)) {
		/* Type 1: with destination address */
		sk_addr->dst.addr = sk_addr->pgn & 0xff;
		/* normalize pgn: strip dst address */
		sk_addr->pgn &= 0x3ff00;
	} else {
		/* set broadcast address */
		sk_addr->dst.addr = J1939_NO_ADDR;
	}
	j1939_recv_ecu_flags(skb, data);
	j1939_recv(skb, j1939_level_can);

	/* restore the original skb, should always work */
	skb_push(skb, CAN_HDR);
	/* no safety check, it just restores the skbuf's contents */
	__skb_trim(skb, orig_len);
	memcpy(sk_addr, saved_cb, sizeof(saved_cb));
}

static int j1939_send_can(struct sk_buff *skb)
{
	int ret, dlc;
	canid_t canid;
	struct j1939_sk_buff_cb *sk_addr;
	struct net_device *netdev = NULL;
	struct can_frame *msg;

	dlc = skb->len;
	if (dlc > 8)
		return -EMSGSIZE;
	ret = pskb_expand_head(skb, SKB_DATA_ALIGN(CAN_HDR),
			CAN_FTR + (8-dlc), GFP_ATOMIC);
	if (ret < 0)
		return ret;

	msg = (void *)skb_push(skb, CAN_HDR);
	BUG_ON(!msg);
	/* make it a full can frame */
	skb_put(skb, CAN_FTR + (8 - dlc));

	sk_addr = (struct j1939_sk_buff_cb *)skb->cb;
	canid = CAN_EFF_FLAG |
		(sk_addr->src.addr & 0xff) |
		((sk_addr->priority & 0x7) << 26);
	if (pgn_is_pdu1(sk_addr->pgn))
		canid |= ((sk_addr->pgn & 0x3ff00) << 8) |
			((sk_addr->dst.addr & 0xff) << 8);
	else
		canid |= ((sk_addr->pgn & 0x3ffff) << 8);

	msg->can_id = canid;
	msg->can_dlc = dlc;

	/* set net_device */
	ret = -ENODEV;
	if (!skb->dev) {
		if (!sk_addr->ifindex)
			goto failed;
		netdev = dev_get_by_index(&init_net, sk_addr->ifindex);
		if (!netdev)
			goto failed;
		skb->dev = netdev;
	}

	/* fix the 'always free' policy of can_send */
	skb = skb_get(skb);
	ret = can_send(skb, 1);
	if (!ret) {
		/* free when can_send succeeded */
		kfree_skb(skb);
		/* is this necessary ? */
		ret = RESULT_STOP;
	}
failed:
	if (netdev)
		dev_put(netdev);
	return ret;
}

static int j1939_send_normalize(struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *cb = (void *)skb->cb;
	struct j1939_segment *jseg;
	struct addr_ent *paddr;
	struct j1939_ecu *ecu;
	int ret = 0;

	/* apply sanity checks */
	cb->pgn &= (pgn_is_pdu1(cb->pgn)) ? 0x3ff00 : 0x3ffff;
	if (cb->priority > 7)
		cb->priority = 6;

	/* verify source */
	if (!cb->ifindex)
		return -ENETUNREACH;
	jseg = j1939_segment_find(cb->ifindex);
	if (!jseg)
		return -ENETUNREACH;
	read_lock_bh(&jseg->lock);
	/* verify source */
	if (cb->src.name) {
		ecu = j1939_ecu_find_by_name(cb->src.name, cb->ifindex);
		cb->src.flags = ecu ? ecu->flags : 0;
		if (ecu)
			put_j1939_ecu(ecu);
	} else if (j1939_address_is_unicast(cb->src.addr)) {
		paddr = &jseg->ents[cb->src.addr];
		cb->src.flags = paddr->flags;
	} else if (cb->src.addr == J1939_IDLE_ADDR) {
		/* allow always */
		cb->src.flags = ECUFLAG_LOCAL;
	} else {
		/* J1939_NO_ADDR */
		cb->src.flags = 0;
	}
	if (cb->src.flags & ECUFLAG_REMOTE) {
		ret = -EREMOTE;
		goto failed;
	} else if (!(cb->src.flags & ECUFLAG_LOCAL)) {
		ret = -EADDRNOTAVAIL;
		goto failed;
	}

	/* verify destination */
	if (cb->dst.name) {
		ecu = j1939_ecu_find_by_name(cb->dst.name, cb->ifindex);
		if (!ecu) {
			ret = -EADDRNOTAVAIL;
			goto failed;
		}
		cb->dst.flags = ecu->flags;
		put_j1939_ecu(ecu);
	} else if (cb->dst.addr == J1939_IDLE_ADDR) {
		/* not a valid destination */
		ret = -EADDRNOTAVAIL;
		goto failed;
	} else if (j1939_address_is_unicast(cb->dst.addr)) {
		paddr = &jseg->ents[cb->dst.addr];
		cb->dst.flags = paddr->flags;
	} else {
		cb->dst.flags = 0;
	}

	ret = 0;
failed:
	read_unlock_bh(&jseg->lock);
	put_j1939_segment(jseg);
	return ret;
}

/* TOPLEVEL interface */
int j1939_recv(struct sk_buff *skb, int level)
{
	int ret;

	/* this stack operates with fallthrough switch statement */
	switch (level) {
	default:
		WARN_ONCE(1, "%s: unsupported level %i\n", __func__, level);
		return 0;
	case j1939_level_can:
		ret = j1939_recv_address_claim(skb);
		if (unlikely(ret))
			break;
		ret = j1939_recv_promisc(skb);
		if (unlikely(ret))
			break;
		ret = j1939_recv_transport(skb);
		if (unlikely(ret))
			break;
	case j1939_level_transport:
	case j1939_level_sky:
		ret = j1939_recv_distribute(skb);
		break;
	}
	if (ret == RESULT_STOP)
		return 0;
	return ret;

}
EXPORT_SYMBOL_GPL(j1939_recv);

int j1939_send(struct sk_buff *skb, int level)
{
	int ret;
	struct sock *sk = NULL;

	/* this stack operates with fallthrough switch statement */
	switch (level) {
	default:
		WARN_ONCE(1, "%s: unsupported level %i\n", __func__, level);
	case j1939_level_sky:
		sk = skb->sk;
		if (sk)
			sock_hold(sk);
		ret = j1939_send_normalize(skb);
		if (unlikely(ret))
			break;
		ret = j1939_send_transport(skb);
		if (unlikely(ret))
			break;
	case j1939_level_transport:
		ret = j1939_send_address_claim(skb);
		if (unlikely(ret))
			break;
	case j1939_level_can:
		ret = j1939_send_can(skb);
		if (RESULT_STOP == ret)
			/* don't mark as stopped, it can't be better */
			ret = 0;
		break;
	}
	if (ret == RESULT_STOP)
		ret = 0;
	else if (!ret && sk)
		j1939_sock_pending_del(sk);
	if (sk)
		sock_put(sk);
	return ret;

}
EXPORT_SYMBOL_GPL(j1939_send);

/* NETDEV MANAGEMENT */

#define J1939_CAN_ID	CAN_EFF_FLAG
#define J1939_CAN_MASK	(CAN_EFF_FLAG | CAN_RTR_FLAG)
int j1939_segment_attach(struct net_device *netdev)
{
	int ret;
	struct j1939_segment *jseg;

	if (!netdev)
		return -ENODEV;
	if (netdev->type != ARPHRD_CAN)
		return -EAFNOSUPPORT;

	ret = j1939_segment_register(netdev);
	if (ret < 0)
		goto fail_register;
	jseg = j1939_segment_find(netdev->ifindex);
	ret = can_rx_register(netdev, J1939_CAN_ID, J1939_CAN_MASK,
			j1939_can_recv, jseg, "j1939");
	if (ret < 0)
		goto fail_can_rx;
	return 0;

fail_can_rx:
	j1939_segment_unregister(jseg);
	put_j1939_segment(jseg);
fail_register:
	return ret;
}

int j1939_segment_detach(struct net_device *netdev)
{
	struct j1939_segment *jseg;

	BUG_ON(!netdev);
	jseg = j1939_segment_find(netdev->ifindex);
	if (!jseg)
		return -EHOSTDOWN;
	can_rx_unregister(netdev, J1939_CAN_ID, J1939_CAN_MASK,
			j1939_can_recv, jseg);
	j1939_segment_unregister(jseg);
	put_j1939_segment(jseg);
	j1939sk_netdev_event(netdev->ifindex, EHOSTDOWN);
	return 0;
}

static int j1939_notifier(struct notifier_block *nb,
			unsigned long msg, void *data)
{
	struct net_device *netdev = (struct net_device *)data;
	struct j1939_segment *jseg;

	if (!net_eq(dev_net(netdev), &init_net))
		return NOTIFY_DONE;

	if (netdev->type != ARPHRD_CAN)
		return NOTIFY_DONE;

	switch (msg) {
	case NETDEV_UNREGISTER:
		jseg = j1939_segment_find(netdev->ifindex);
		if (!jseg)
			break;
		j1939_segment_unregister(jseg);
		j1939sk_netdev_event(netdev->ifindex, ENODEV);
		break;

	case NETDEV_DOWN:
		j1939sk_netdev_event(netdev->ifindex, ENETDOWN);
		break;
	}

	return NOTIFY_DONE;
}

/* MODULE interface */

static __init int j1939_module_init(void)
{
	int ret;

	pr_info("can: SAE J1939\n");

	ret = j1939_proc_module_init();
	if (ret < 0)
		goto fail_proc;

	s.notifier.notifier_call = j1939_notifier;
	register_netdevice_notifier(&s.notifier);

	ret = j1939bus_module_init();
	if (ret < 0)
		goto fail_bus;
	ret = j1939sk_module_init();
	if (ret < 0)
		goto fail_sk;
	ret = j1939tp_module_init();
	if (ret < 0)
		goto fail_tp;
	return 0;

	j1939tp_module_exit();
fail_tp:
	j1939sk_module_exit();
fail_sk:
	j1939bus_module_exit();
fail_bus:
	unregister_netdevice_notifier(&s.notifier);

	j1939_proc_module_exit();
fail_proc:
	return ret;
}

static __exit void j1939_module_exit(void)
{
	j1939tp_module_exit();
	j1939sk_module_exit();
	j1939bus_module_exit();

	unregister_netdevice_notifier(&s.notifier);

	j1939_proc_module_exit();
}

module_init(j1939_module_init);
module_exit(j1939_module_exit);
