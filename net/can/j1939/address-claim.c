/*
 * Copyright (c) 2010-2011 EIA Electronics
 *
 * Authors:
 * Pieter Beyens <pieter.beyens@eia.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 */

/*
 * J1939 Address Claiming.
 * Address Claiming in the kernel
 * - keeps track of the AC states of ECU's,
 * - resolves NAME<=>SA taking into account the AC states of ECU's.
 *
 * All Address Claim msgs (including host-originated msg) are processed
 * at the receive path (a sent msg is always received again via CAN echo).
 * As such, the processing of AC msgs is done in the order on which msgs
 * are sent on the bus.
 *
 * This module doesn't send msgs itself (e.g. replies on Address Claims),
 * this is the responsibility of a user space application or daemon.
 */

#include <linux/skbuff.h>
#include <linux/byteorder/generic.h>

#include "j1939-priv.h"

#define CANDATA2NAME(data) le64_to_cpup((uint64_t *)data)

static inline int ac_msg_is_request_for_ac(struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *sk_addr = (void *)skb->cb;
	int req_pgn;

	if ((skb->len < 3) || (sk_addr->pgn != PGN_REQUEST))
		return 0;
	req_pgn = skb->data[0] | (skb->data[1] << 8) | (skb->data[2] << 16);
	return req_pgn == PGN_ADDRESS_CLAIMED;
}

static int j1939_verify_outgoing_address_claim(struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *sk_addr = (void *)skb->cb;

	if (skb->len != 8) {
		j1939_notice("tx address claim with dlc %i\n", skb->len);
		return -EPROTO;
	}

	if (sk_addr->src.name != CANDATA2NAME(skb->data)) {
		j1939_notice("tx address claim with different name\n");
		return -EPROTO;
	}

	if (sk_addr->src.addr == J1939_NO_ADDR) {
		j1939_notice("tx address claim with broadcast sa\n");
		return -EPROTO;
	}

	/* ac must always be a broadcast */
	if (sk_addr->dst.name || (sk_addr->dst.addr != J1939_NO_ADDR)) {
		j1939_notice("tx address claim with dest, not broadcast\n");
		return -EPROTO;
	}
	return 0;
}

int j1939_send_address_claim(struct sk_buff *skb)
{
	int ret, sa;
	struct j1939_sk_buff_cb *sk_addr = (void *)skb->cb;

	/* network mgmt: address claiming msgs */
	if (sk_addr->pgn == PGN_ADDRESS_CLAIMED) {
		struct j1939_ecu *ecu;

		ret = j1939_verify_outgoing_address_claim(skb);
		/* return both when failure & when successfull */
		if (ret < 0)
			return ret;
		ecu = j1939_ecu_find_by_name(sk_addr->src.name,
				sk_addr->ifindex);
		if (!ecu)
			return -ENODEV;
		if (!(ecu->flags & ECUFLAG_LOCAL)) {
			put_j1939_ecu(ecu);
			return -EREMOTE;
		}

		if (ecu->sa != sk_addr->src.addr)
			/* hold further traffic for ecu, remove from parent */
			j1939_ecu_remove_sa(ecu);
		put_j1939_ecu(ecu);
	} else if (sk_addr->src.name) {
		/* assign source address */
		sa = j1939_name_to_sa(sk_addr->src.name, sk_addr->ifindex);
		if (!j1939_address_is_unicast(sa) &&
				!ac_msg_is_request_for_ac(skb)) {
			j1939_notice("tx drop: invalid sa for name "
					"0x%016llx\n", sk_addr->src.name);
			return -EADDRNOTAVAIL;
		}
		sk_addr->src.addr = sa;
	}

	/* assign destination address */
	if (sk_addr->dst.name) {
		sa = j1939_name_to_sa(sk_addr->dst.name, sk_addr->ifindex);
		if (!j1939_address_is_unicast(sa)) {
			j1939_notice("tx drop: invalid da for name "
					"0x%016llx\n", sk_addr->dst.name);
			return -EADDRNOTAVAIL;
		}
		sk_addr->dst.addr = sa;
	}
	return 0;
}

static struct j1939_ecu *j1939_process_address_claim(struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *sk_addr = (void *)skb->cb;
	struct j1939_ecu *ecu, *dut, **pref;
	name_t name;

	if (skb->len < 8) {
		j1939_notice("rx address claim with wrong dlc %i\n", skb->len);
		return ERR_PTR(-EPROTO);
	}

	name = CANDATA2NAME(skb->data);
	if (!name) {
		j1939_notice("rx address claim without name\n");
		return ERR_PTR(-EPROTO);
	}

	if (!j1939_address_is_valid(sk_addr->src.addr)) {
		j1939_notice("rx address claim with broadcast sa\n");
		return ERR_PTR(-EPROTO);
	}

	ecu = j1939_ecu_get_register(name, sk_addr->ifindex, ECUFLAG_REMOTE, 1);
	if (IS_ERR(ecu))
		return ecu;
	if ((ecu->flags & ECUFLAG_LOCAL) && !skb->sk)
		j1939_warning("duplicate name on the bus %016llx!\n",
				(long long)name);

	if (sk_addr->src.addr >= J1939_IDLE_ADDR) {
		j1939_ecu_remove_sa(ecu);
		if (ecu->flags & ECUFLAG_REMOTE)
			/* extra put => schedule removal */
			j1939_ecu_unregister(ecu);
		return ecu;
	}

	write_lock_bh(&ecu->parent->lock);
	/* save new SA */
	if (sk_addr->src.addr != ecu->sa)
		j1939_ecu_remove_sa_locked(ecu);
	ecu->sa = sk_addr->src.addr;
	/* iterate this segment */
	list_for_each_entry(dut, &ecu->parent->ecus, list) {
		/* cancel pending claims for this SA */
		/* this includes myself ! */
		if (ecu->sa == dut->sa)
			/*
			 * cancel pending claims for our new SA
			 * this includes 'ecu', since we will
			 * schedule a timer soon now
			 */
			hrtimer_try_to_cancel(&dut->ac_timer);
		if ((ecu->sa == dut->sa) && (dut->name > ecu->name))
			dut->sa = J1939_IDLE_ADDR;
	}

	pref = &ecu->parent->ents[sk_addr->src.addr].ecu;
	if (*pref && ((*pref)->name > ecu->name))
		*pref = NULL;

	/* schedule timer in 250 msec to commit address change */
	hrtimer_start(&ecu->ac_timer, ktime_set(0, 250000000),
			HRTIMER_MODE_REL);
	write_unlock_bh(&ecu->parent->lock);

	return ecu;
}

int j1939_recv_address_claim(struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *sk_addr = (void *)skb->cb;
	struct j1939_ecu *ecu;

	/*
	 * network mgmt
	 */
	if (sk_addr->pgn == PGN_ADDRESS_CLAIMED) {
		ecu = j1939_process_address_claim(skb);
		if (IS_ERR(ecu))
			return PTR_ERR(ecu);
	} else if (j1939_address_is_unicast(sk_addr->src.addr)) {
		ecu = j1939_ecu_find_by_addr(sk_addr->src.addr,
				sk_addr->ifindex);
	} else {
		ecu = NULL;
	}

	/* assign source stuff */
	if (ecu) {
		ecu->rxtime = ktime_get();
		sk_addr->src.flags = ecu->flags;
		sk_addr->src.name = ecu->name;
		put_j1939_ecu(ecu);
	}
	/* assign destination stuff */
	ecu = j1939_ecu_find_by_addr(sk_addr->dst.addr, sk_addr->ifindex);
	if (ecu) {
		sk_addr->dst.flags = ecu->flags;
		sk_addr->dst.name = ecu->name;
		put_j1939_ecu(ecu);
	}
	return 0;
}

