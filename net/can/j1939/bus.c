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

/*
 * j1939-bus.c - bus for j1939 remote devices
 * Since rtnetlink, no real bus is used.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/workqueue.h>

#include "j1939-priv.h"

#define jseg_dbg(jseg, fmt, ...) \
	pr_debug("j1939-%i: " fmt, (jseg)->ifindex, ##__VA_ARGS__)

#define ecu_dbg(ecu, fmt, ...) \
	pr_debug("j1939-%i,%016llx,%02x: " fmt, (ecu)->parent->ifindex, \
		(ecu)->name, (ecu)->sa, ##__VA_ARGS__)
#define ecu_alert(ecu, fmt, ...) \
	pr_alert("j1939-%i,%016llx,%02x: " fmt, (ecu)->parent->ifindex, \
		(ecu)->name, (ecu)->sa, ##__VA_ARGS__)

static struct {
	struct list_head list;
	spinlock_t lock;
} segments;

struct j1939_segment *j1939_segment_find(int ifindex)
{
	struct j1939_segment *jseg;

	spin_lock_bh(&segments.lock);
	list_for_each_entry(jseg, &segments.list, flist) {
		if (jseg->ifindex == ifindex) {
			get_j1939_segment(jseg);
			goto found;
		}
	}
	jseg = NULL;
found:
	spin_unlock_bh(&segments.lock);
	return jseg;
}

/*
 * iterate over ECU's,
 * and register flagged ecu's on their claimed SA
 */
static void j1939_segment_ac_task(unsigned long val)
{
	struct j1939_segment *jseg = (void *)val;
	struct j1939_ecu *ecu;

	write_lock_bh(&jseg->lock);
	list_for_each_entry(ecu, &jseg->ecus, list) {
		/* next 2 (read & set) could be merged into xxx? */
		if (!atomic_read(&ecu->ac_delay_expired))
			continue;
		atomic_set(&ecu->ac_delay_expired, 0);
		if (j1939_address_is_unicast(ecu->sa))
			ecu->parent->ents[ecu->sa].ecu = ecu;
	}
	write_unlock_bh(&jseg->lock);
}
/*
 * segment device interface
 */
static void cb_put_j1939_segment(struct kref *kref)
{
	struct j1939_segment *jseg =
		container_of(kref, struct j1939_segment, kref);

	tasklet_disable_nosync(&jseg->ac_task);
	kfree(jseg);
}

void put_j1939_segment(struct j1939_segment *segment)
{
	kref_put(&segment->kref, cb_put_j1939_segment);
}

int j1939_segment_register(struct net_device *netdev)
{
	int ret;
	struct j1939_segment *jseg;

	jseg = j1939_segment_find(netdev->ifindex);
	if (jseg) {
		put_j1939_segment(jseg);
		ret = -EALREADY;
		goto fail_exist;
	}
	jseg = kzalloc(sizeof(*jseg), GFP_KERNEL);
	if (!jseg) {
		ret = -ENOMEM;
		goto fail_malloc;
	}
	tasklet_init(&jseg->ac_task, j1939_segment_ac_task,
			(unsigned long)jseg);
	rwlock_init(&jseg->lock);
	INIT_LIST_HEAD(&jseg->ecus);
	INIT_LIST_HEAD(&jseg->flist);
	jseg->ifindex = netdev->ifindex;

	kref_init(&jseg->kref);

	spin_lock_bh(&segments.lock);
	list_add_tail(&jseg->flist, &segments.list);
	spin_unlock_bh(&segments.lock);

	jseg_dbg(jseg, "register\n");
	return 0;

fail_malloc:
fail_exist:
	return ret;
}

void j1939_segment_unregister(struct j1939_segment *jseg)
{
	struct j1939_ecu *ecu;

	if (!jseg)
		return;

	spin_lock_bh(&segments.lock);
	list_del_init(&jseg->flist);
	spin_unlock_bh(&segments.lock);

	write_lock_bh(&jseg->lock);
	while (!list_empty(&jseg->ecus)) {
		ecu = list_first_entry(&jseg->ecus, struct j1939_ecu, list);
		write_unlock_bh(&jseg->lock);
		j1939_ecu_unregister(ecu);
		write_lock_bh(&jseg->lock);
	}
	write_unlock_bh(&jseg->lock);
	jseg_dbg(jseg, "unregister\n");
	put_j1939_segment(jseg);
}

/*
 * ECU device interface
 */
static enum hrtimer_restart j1939_ecu_timer_handler(struct hrtimer *hrtimer)
{
	struct j1939_ecu *ecu =
		container_of(hrtimer, struct j1939_ecu, ac_timer);

	atomic_set(&ecu->ac_delay_expired, 1);
	tasklet_schedule(&ecu->parent->ac_task);
	return HRTIMER_NORESTART;
}

static void cb_put_j1939_ecu(struct kref *kref)
{
	struct j1939_ecu *ecu =container_of(kref, struct j1939_ecu, kref);

	kfree(ecu);
}
void put_j1939_ecu(struct j1939_ecu *ecu)
{
	kref_put(&ecu->kref, cb_put_j1939_ecu);
}

struct j1939_ecu *j1939_ecu_get_register(name_t name, int ifindex, int flags,
		int return_existing)
{
	struct j1939_segment *parent;
	struct j1939_ecu *ecu, *dut;

	if (!ifindex || !name) {
		pr_alert("%s(%i, %016llx) invalid\n",
				__func__, ifindex, (long long)name);
		return ERR_PTR(-EINVAL);
	}

	parent = j1939_segment_find(ifindex);
	if (!parent) {
		pr_alert("%s %i: segment not found\n", __func__, ifindex);
		return ERR_PTR(-EINVAL);
	}
	if (return_existing) {
		read_lock_bh(&parent->lock);
		/* test for existing name */
		list_for_each_entry(dut, &parent->ecus, list) {
			if (dut->name == name) {
				get_j1939_ecu(dut);
				read_unlock_bh(&parent->lock);
				return dut;
			}
		}
		read_unlock_bh(&parent->lock);
	}
	/* alloc */
	ecu = kzalloc(sizeof(*ecu), gfp_any());
	if (!ecu)
		/* should we look for an existing ecu */
		return ERR_PTR(-ENOMEM);
	kref_init(&ecu->kref);
	ecu->sa = J1939_IDLE_ADDR;
	ecu->name = name;
	ecu->flags = flags;

	hrtimer_init(&ecu->ac_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	ecu->ac_timer.function = j1939_ecu_timer_handler;
	INIT_LIST_HEAD(&ecu->list);

	/* first add to internal list */
	write_lock_bh(&parent->lock);
	/* test for duplicate name */
	list_for_each_entry(dut, &parent->ecus, list) {
		if (dut->name == ecu->name)
			goto duplicate;
	}
	get_j1939_ecu(ecu);
	/* a ref to parent is held */
	ecu->parent = parent;
	list_add_tail(&ecu->list, &parent->ecus);
	write_unlock_bh(&parent->lock);
	ecu_dbg(ecu, "register\n");
	return ecu;

duplicate:
	get_j1939_ecu(dut);
	write_unlock_bh(&parent->lock);
	put_j1939_segment(parent);
	if (return_existing)
		return dut;
	ecu_alert(ecu, "duplicate name\n");
	put_j1939_ecu(ecu);
	return ERR_PTR(-EEXIST);
}

void j1939_ecu_unregister(struct j1939_ecu *ecu)
{
	BUG_ON(!ecu);
	ecu_dbg(ecu, "unregister\n");
	hrtimer_try_to_cancel(&ecu->ac_timer);

	write_lock_bh(&ecu->parent->lock);
	j1939_ecu_remove_sa_locked(ecu);
	list_del_init(&ecu->list);
	write_unlock_bh(&ecu->parent->lock);
	/* put segment, reverting the effect done by ..._register() */
	put_j1939_segment(ecu->parent);
	put_j1939_ecu(ecu);
}

struct j1939_ecu *j1939_ecu_find_by_addr(int sa, int ifindex)
{
	struct j1939_ecu *ecu;
	struct j1939_segment *parent;

	if (!j1939_address_is_unicast(sa))
		return NULL;
	parent = j1939_segment_find(ifindex);
	if (!parent)
		return NULL;
	read_lock_bh(&parent->lock);
	ecu = parent->ents[sa].ecu;
	if (ecu)
		get_j1939_ecu(ecu);
	read_unlock_bh(&parent->lock);
	put_j1939_segment(parent);
	return ecu;
}

int j1939_name_to_sa(uint64_t name, int ifindex)
{
	struct j1939_ecu *ecu;
	struct j1939_segment *parent;
	int sa;

	if (!name)
		return J1939_IDLE_ADDR;
	parent = j1939_segment_find(ifindex);
	if (!parent)
		return J1939_IDLE_ADDR;

	sa = J1939_IDLE_ADDR;
	read_lock_bh(&parent->lock);
	list_for_each_entry(ecu, &parent->ecus, list) {
		if (ecu->name == name) {
			if ((sa == J1939_IDLE_ADDR) &&
			    (parent->ents[ecu->sa].ecu == ecu))
				/* ecu's SA is registered */
				sa = ecu->sa;
			break;
		}
	}
	read_unlock_bh(&parent->lock);
	put_j1939_segment(parent);
	return sa;
}

struct j1939_ecu *j1939_ecu_find_segment_default_tx(int ifindex,
		name_t *name, uint8_t *addr)
{
	struct j1939_ecu *ecu;
	struct j1939_segment *parent;
	struct addr_ent *paddr;
	int j;

	if (ifindex <= 0)
		return ERR_PTR(-EINVAL);
	parent = j1939_segment_find(ifindex);
	if (!parent)
		return ERR_PTR(-ENETUNREACH);
	read_lock_bh(&parent->lock);
	list_for_each_entry(ecu, &parent->ecus, list) {
		if (ecu->flags & ECUFLAG_LOCAL) {
			get_j1939_ecu(ecu);
			if (name)
				*name = ecu->name;
			if (addr)
				*addr = ecu->sa;
			goto found;
		}
	}
	ecu = NULL;
	for (j = 0, paddr = parent->ents; j < J1939_IDLE_ADDR; ++j, ++paddr) {
		if (paddr->ecu)
			continue;
		if (paddr->flags & ECUFLAG_LOCAL) {
			if (name)
				*name = 0;
			if (addr)
				*addr = j;
			goto found;
		}
	}
	ecu = ERR_PTR(-EHOSTDOWN);
found:
	read_unlock_bh(&parent->lock);
	put_j1939_segment(parent);
	return ecu;
}

/* ecu lookup helper */
static struct j1939_ecu *_j1939_ecu_find_by_name(name_t name,
		struct j1939_segment *jseg)
{
	struct j1939_ecu *ecu;

	read_lock_bh(&jseg->lock);
	list_for_each_entry(ecu, &jseg->ecus, list) {
		if (ecu->name == name) {
			get_j1939_ecu(ecu);
			goto found_on_intf;
		}
	}
	ecu = NULL;
found_on_intf:
	read_unlock_bh(&jseg->lock);
	return ecu;
}

/* ecu lookup by name */
struct j1939_ecu *j1939_ecu_find_by_name(name_t name, int ifindex)
{
	struct j1939_ecu *ecu;
	struct j1939_segment *jseg;

	if (!name)
		return NULL;
	if (ifindex) {
		jseg = j1939_segment_find(ifindex);
		if (!jseg)
			return NULL;
		ecu = _j1939_ecu_find_by_name(name, jseg);
		put_j1939_segment(jseg);
		return ecu;
	}
	/* iterate segments */
	spin_lock_bh(&segments.lock);
	list_for_each_entry(jseg, &segments.list, flist) {
		get_j1939_segment(jseg);
		ecu = _j1939_ecu_find_by_name(name, jseg);
		put_j1939_segment(jseg);
		if (ecu)
			goto found;
	}
	ecu = NULL;
found:
	spin_unlock_bh(&segments.lock);
	return ecu;
}

/* PROC */
static int j1939_proc_addr(struct seq_file *sqf, void *v)
{
	struct j1939_segment *jseg;
	struct net_device *netdev;
	struct addr_ent *paddr;
	int j, flags;
	ktime_t now;
	struct timeval tv;

	now = ktime_get();
	seq_printf(sqf, "iface\tSA\tflags\trxtime\n");
	spin_lock_bh(&segments.lock);
	list_for_each_entry(jseg, &segments.list, flist) {
		get_j1939_segment(jseg);
		netdev = dev_get_by_index(&init_net, jseg->ifindex);
		if (!netdev) {
			pr_alert("j1939 proc: ifindex %i not found\n",
				jseg->ifindex);
			put_j1939_segment(jseg);
			continue;
		}
		read_lock_bh(&jseg->lock);
		for (j = 0, paddr = jseg->ents; j < J1939_IDLE_ADDR;
				++j, ++paddr) {
			flags = paddr->flags;
			if (paddr->ecu)
				flags |= paddr->ecu->flags;
			tv = ktime_to_timeval(ktime_sub(now, paddr->rxtime));
			if (!paddr->flags && !paddr->ecu)
				continue;
			seq_printf(sqf, "%s\t%02x\t%c%c%c%c\t-%lu.%06lu\n",
				netdev->name, j,
				(flags & ECUFLAG_LOCAL) ? 'L' : '-',
				(flags & ECUFLAG_REMOTE) ? 'R' : '-',
				(paddr->flags) ? 'S' : '-',
				paddr->ecu ? 'E' : '-',
				tv.tv_sec, tv.tv_usec);
		}
		read_unlock_bh(&jseg->lock);
		dev_put(netdev);
		put_j1939_segment(jseg);
	}
	spin_unlock_bh(&segments.lock);
	return 0;
}

static int j1939_proc_ecu(struct seq_file *sqf, void *v)
{
	struct j1939_segment *jseg;
	struct j1939_ecu *ecu;
	struct net_device *netdev;
	ktime_t now;
	struct timeval tv;
	char sa[4];

	now = ktime_get();
	seq_printf(sqf, "iface\taddr\tname\tflags\trxtime\n");
	spin_lock_bh(&segments.lock);
	list_for_each_entry(jseg, &segments.list, flist) {
		get_j1939_segment(jseg);
		netdev = dev_get_by_index(&init_net, jseg->ifindex);
		if (!netdev) {
			pr_alert("j1939 proc: ifindex %i not found\n",
				jseg->ifindex);
			put_j1939_segment(jseg);
			continue;
		}
		read_lock_bh(&jseg->lock);
		list_for_each_entry(ecu, &jseg->ecus, list) {
			tv = ktime_to_timeval(ktime_sub(now, ecu->rxtime));
			if (j1939_address_is_unicast(ecu->sa) &&
				(ecu->parent->ents[ecu->sa].ecu == ecu))
				snprintf(sa, sizeof(sa), "%02x", ecu->sa);
			else
				strcpy(sa, "-");
			seq_printf(sqf, "%s\t%s\t%016llx\t%c\t-%lu.%06lu\n",
				netdev->name, sa,
				(unsigned long long)ecu->name,
				(ecu->flags & ECUFLAG_LOCAL) ? 'L' : 'R',
				tv.tv_sec, tv.tv_usec);
		}
		read_unlock_bh(&jseg->lock);
		dev_put(netdev);
		put_j1939_segment(jseg);
	}
	spin_unlock_bh(&segments.lock);
	return 0;
}

/* exported init */
int __init j1939bus_module_init(void)
{
	INIT_LIST_HEAD(&segments.list);
	spin_lock_init(&segments.lock);
	j1939_proc_add("addr", j1939_proc_addr, NULL);
	j1939_proc_add("ecu", j1939_proc_ecu, NULL);
	return 0;
}

void j1939bus_module_exit(void)
{
	struct j1939_segment *jseg;
	struct net_device *netdev;

	spin_lock_bh(&segments.lock);
	while (!list_empty(&segments.list)) {
		jseg = list_first_entry(&segments.list,
				struct j1939_segment, flist);
		netdev = dev_get_by_index(&init_net, jseg->ifindex);
		spin_unlock_bh(&segments.lock);
		j1939_segment_detach(netdev);
		dev_put(netdev);
		spin_lock_bh(&segments.lock);
	}
	spin_unlock_bh(&segments.lock);

	j1939_proc_remove("ecu");
	j1939_proc_remove("addr");
}


