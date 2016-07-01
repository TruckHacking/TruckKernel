/*
 * j1939-priv.h
 *
 * Copyright (c) 2010-2011 EIA Electronics
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _J1939_PRIV_H_
#define _J1939_PRIV_H_

#include <linux/kref.h>
#include <linux/list.h>
#include <net/sock.h>

#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/can/j1939.h>
#include <linux/atomic.h>
#include <linux/interrupt.h>

/* TODO: return ENETRESET on busoff. */

#define ECUFLAG_LOCAL	0x01
#define ECUFLAG_REMOTE	0x02

#define PGN_REQUEST		0x0ea00
#define PGN_ADDRESS_CLAIMED	0x0ee00
#define PGN_MAX			0x3ffff

#define SA_MAX_UNICAST	0xfd
/*
 * j1939 devices
 */
struct j1939_ecu {
	struct list_head list;
	ktime_t rxtime;
	name_t name;
	int flags;
	uint8_t sa;
	/*
	 * atomic flag, set by ac_timer
	 * cleared/processed by segment's tasklet
	 * indicates that this ecu successfully claimed @sa as its address
	 * By communicating this from the ac_timer event to segments tasklet,
	 * a context locking problem is solved. All other 'ecu readers'
	 * must only lock with _bh, not with _irq.
	 */
	atomic_t ac_delay_expired;
	struct hrtimer ac_timer;
	struct kref kref;
	struct j1939_segment *parent;
};
#define to_j1939_ecu(x) container_of((x), struct j1939_ecu, dev)

struct j1939_segment {
	struct list_head ecus; /*
	 * local list entry in parent
	 * These allow irq (& softirq) context lookups on j1939 devices
	 * This approach (seperate lists) is done as the other 2 alternatives
	 * are not easier or even wrong
	 * 1) using the pure kobject methods involves mutexes, which are not
	 *    allowed in irq context.
	 * 2) duplicating data structures would require a lot of synchronization
	 *    code
	 * usage:
	 */
	rwlock_t lock; /*
	 * segments need a lock to protect the above list
	 */
	struct list_head flist; /*
	 * list entry for use by interrupt lookup routines
	 */
	int ifindex;
	struct addr_ent {
		ktime_t rxtime;
		struct j1939_ecu *ecu;
		int flags;
	} ents[256];

	/*
	 * tasklet to process ecu address claimed events.
	 * These events raise in hardirq context. Signalling the event
	 * and scheduling this tasklet successfully moves the
	 * event to softirq context
	 */
	struct tasklet_struct ac_task;
	/*
	 * list of 256 ecu ptrs, that cache the claimed addresses.
	 * also protected by the above lock
	 * don't use directly, use j1939_ecu_set_address() instead
	 */
	struct kref kref;
};
#define to_j1939_segment(x) container_of((x), struct j1939_segment, dev)

extern void put_j1939_ecu(struct j1939_ecu *ecu);
extern void put_j1939_segment(struct j1939_segment *segment);
static inline struct j1939_ecu *get_j1939_ecu(struct j1939_ecu *dut)
{
	kref_get(&dut->kref);
	return dut;
}
static inline struct j1939_segment *get_j1939_segment(struct j1939_segment *dut)
{
	kref_get(&dut->kref);
	return dut;
}

/*
 * conversion function between (struct sock | struct sk_buff)->sk_priority
 * from linux and j1939 priority field
 */
static inline int j1939_prio(int sk_priority)
{
	if (sk_priority < 0)
		return 6; /* default */
	else if (sk_priority > 7)
		return 0;
	else
		return 7 - sk_priority;
}
static inline int j1939_to_sk_priority(int j1939_prio)
{
	return 7 - j1939_prio;
}

static inline int j1939_address_is_valid(uint8_t sa)
{
	return sa != J1939_NO_ADDR;
}

static inline int j1939_address_is_unicast(uint8_t sa)
{
	return sa <= SA_MAX_UNICAST;
}

static inline int pgn_is_pdu1(pgn_t pgn)
{
	/* ignore dp & res bits for this */
	return (pgn & 0xff00) < 0xf000;
}

static inline int pgn_is_valid(pgn_t pgn)
{
	return pgn <= PGN_MAX;
}

/* utility to correctly unregister a SA */
static inline void j1939_ecu_remove_sa_locked(struct j1939_ecu *ecu)
{
	if (!j1939_address_is_unicast(ecu->sa))
		return;
	if (ecu->parent->ents[ecu->sa].ecu == ecu)
		ecu->parent->ents[ecu->sa].ecu = NULL;
}

static inline void j1939_ecu_remove_sa(struct j1939_ecu *ecu)
{
	if (!j1939_address_is_unicast(ecu->sa))
		return;
	write_lock_bh(&ecu->parent->lock);
	j1939_ecu_remove_sa_locked(ecu);
	write_unlock_bh(&ecu->parent->lock);
}

extern int j1939_name_to_sa(uint64_t name, int ifindex);
extern struct j1939_ecu *j1939_ecu_find_by_addr(int sa, int ifindex);
extern struct j1939_ecu *j1939_ecu_find_by_name(name_t name, int ifindex);
/* find_by_name, with kref & read_lock taken */
extern struct j1939_ecu *j1939_ecu_find_segment_default_tx(
		int ifindex, name_t *pname, uint8_t *paddr);

extern void j1939_put_promisc_receiver(int ifindex);
extern void j1939_get_promisc_receiver(int ifindex);

extern int j1939_proc_add(const char *file,
		int (*seq_show)(struct seq_file *sqf, void *v),
		write_proc_t write);
extern void j1939_proc_remove(const char *file);

extern const char j1939_procname[];
/* j1939 printk */
#define j1939_printk(level, ...) printk(level "J1939 " __VA_ARGS__)

#define j1939_err(...)		j1939_printk(KERN_ERR , __VA_ARGS__)
#define j1939_warning(...)	j1939_printk(KERN_WARNING , __VA_ARGS__)
#define j1939_notice(...)	j1939_printk(KERN_NOTICE , __VA_ARGS__)
#define j1939_info(...)		j1939_printk(KERN_INFO , __VA_ARGS__)
#ifdef DEBUG
#define j1939_debug(...)	j1939_printk(KERN_DEBUG , __VA_ARGS__)
#else
#define j1939_debug(...)
#endif

struct sk_buff;

/* control buffer of the sk_buff */
struct j1939_sk_buff_cb {
	int ifindex;
	priority_t priority;
	struct {
		name_t name;
		uint8_t addr;
		int flags;
	} src, dst;
	pgn_t pgn;
	int msg_flags;
	/* for tx, MSG_SYN will be used to sync on sockets */
};
#define J1939_MSG_RESERVED	MSG_SYN
#define J1939_MSG_SYNC		MSG_SYN

static inline int j1939cb_is_broadcast(const struct j1939_sk_buff_cb *cb)
{
	return (!cb->dst.name && (cb->dst.addr >= 0xff));
}

/* J1939 stack */
enum {
	j1939_level_can,
	j1939_level_transport,
	j1939_level_sky,
};

#define RESULT_STOP	1
/*
 * return RESULT_STOP when stack processing may stop.
 * it is up to the stack entry itself to kfree_skb() the sk_buff
 */

extern int j1939_send(struct sk_buff *, int level);
extern int j1939_recv(struct sk_buff *, int level);

/* stack entries */
extern int j1939_recv_promisc(struct sk_buff *);
extern int j1939_send_transport(struct sk_buff *);
extern int j1939_recv_transport(struct sk_buff *);
extern int j1939_send_address_claim(struct sk_buff *);
extern int j1939_recv_address_claim(struct sk_buff *);

extern int j1939_recv_distribute(struct sk_buff *);

/* network management */
/*
 * j1939_ecu_get_register
 * 'create' & 'register' & 'get' new ecu
 * when a matching ecu already exists, the behaviour depends
 * on @return_existing.
 * when @return_existing is 0, -EEXISTS is returned
 * when @return_exsiting is 1, that ecu is 'get' & returned.
 * @flags is only used when creating new ecu.
 */
extern struct j1939_ecu *j1939_ecu_get_register(name_t name, int ifindex,
		int flags, int return_existing);
extern void j1939_ecu_unregister(struct j1939_ecu *);

extern int j1939_segment_attach(struct net_device *);
extern int j1939_segment_detach(struct net_device *);

extern int j1939_segment_register(struct net_device *);
extern void j1939_segment_unregister(struct j1939_segment *);
extern struct j1939_segment *j1939_segment_find(int ifindex);

extern void j1939sk_netdev_event(int ifindex, int error_code);

/* add/remove receiver */
extern int j1939_recv_add(void *vp, void (*fn)(struct sk_buff *, void *));
extern int j1939_recv_remove(void *vp, void (*fn)(struct sk_buff *, void *));

/*
 * provide public access to this lock
 * so sparse can verify the context balance
 */
extern rwlock_t j1939_receiver_rwlock;
static inline void j1939_recv_suspend(void)
{
	write_lock_bh(&j1939_receiver_rwlock);
}

static inline void j1939_recv_resume(void)
{
	write_unlock_bh(&j1939_receiver_rwlock);
}

/* locks the recv module */
extern void j1939_recv_suspend(void);
extern void j1939_recv_resume(void);

/*
 * decrement pending skb for a j1939 socket
 */
extern void j1939_sock_pending_del(struct sock *sk);

/* seperate module-init/modules-exit's */
extern __init int j1939_proc_module_init(void);
extern __init int j1939bus_module_init(void);
extern __init int j1939sk_module_init(void);
extern __init int j1939tp_module_init(void);

extern void j1939_proc_module_exit(void);
extern void j1939bus_module_exit(void);
extern void j1939sk_module_exit(void);
extern void j1939tp_module_exit(void);

/* rtnetlink */
extern const struct rtnl_af_ops j1939_rtnl_af_ops;
extern int j1939rtnl_new_addr(struct sk_buff *, struct nlmsghdr *, void *arg);
extern int j1939rtnl_del_addr(struct sk_buff *, struct nlmsghdr *, void *arg);
extern int j1939rtnl_dump_addr(struct sk_buff *, struct netlink_callback *);

#endif /* _J1939_PRIV_H_ */
