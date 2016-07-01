/*
 * Copyright (c) 2010-2011 EIA Electronics
 *
 * Authors:
 * Pieter Beyens <pieter.beyens@eia.be>
 * Kurt Van Dijck <kurt.van.dijck@eia.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 */

#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include "j1939-priv.h"

static LIST_HEAD(filters);
DEFINE_RWLOCK(j1939_receiver_rwlock); /* protects the filter list */

struct filter {
	struct list_head list;
	void *vp;
	void (*fn)(struct sk_buff *, void *);
};

int j1939_recv_distribute(struct sk_buff *skb)
{
	struct filter *filter;

	read_lock_bh(&j1939_receiver_rwlock);
	list_for_each_entry(filter, &filters, list)
		filter->fn(skb, filter->vp);
	read_unlock_bh(&j1939_receiver_rwlock);

	return 0;
}

int j1939_recv_add(void *vp, void (*fn)(struct sk_buff *, void *))
{
	struct filter *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;

	f->vp = vp;
	f->fn = fn;

	j1939_recv_suspend();
	list_add(&f->list, &filters);
	j1939_recv_resume();
	return 0;
}

int j1939_recv_remove(void *vp, void (*fn)(struct sk_buff *, void *))
{
	struct filter *filter;
	int found = 0;

	j1939_recv_suspend();
	list_for_each_entry(filter, &filters, list) {
		if ((filter->vp == vp) && (filter->fn == fn)) {
			list_del_init(&filter->list);
			kfree(filter);
			found = 1;
			break;
		}
	}
	j1939_recv_resume();
	return found ? 0 : -ENOENT;
}

