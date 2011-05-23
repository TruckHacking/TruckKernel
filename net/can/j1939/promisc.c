/*
 * Copyright (c) 2010-2011 EIA Electronics
 *
 * Authors:
 * Kurt Van Dijck <kurt.van.dijck@eia.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 */

#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/sysctl.h>
#include "j1939-priv.h"

static atomic_t n_promisc = ATOMIC_INIT(0);

void j1939_get_promisc_receiver(int ifindex)
{
	atomic_inc(&n_promisc);
}
EXPORT_SYMBOL_GPL(j1939_get_promisc_receiver);

void j1939_put_promisc_receiver(int ifindex)
{
	atomic_dec(&n_promisc);
}
EXPORT_SYMBOL_GPL(j1939_put_promisc_receiver);

int j1939_recv_promisc(struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *cb = (void *)skb->cb;

	if ((cb->src.flags & ECUFLAG_REMOTE) &&
		(cb->dst.flags & ECUFLAG_REMOTE)) {
		if (!atomic_read(&n_promisc))
			/* stop receive path */
			return RESULT_STOP;
	}
	return 0;
}

