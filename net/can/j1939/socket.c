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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/list.h>
#include <linux/if_arp.h>
#include <net/tcp_states.h>

#include <linux/can/core.h>
#include <linux/can/j1939.h>
#include "j1939-priv.h"

struct j1939_sock {
	struct sock sk; /* must be first to skip with memset */
	struct list_head list;

	int state;
	#define JSK_BOUND	BIT(0)
	#define JSK_CONNECTED	BIT(1)
	#define PROMISC		BIT(2)
	#define RECV_OWN	BIT(3)

	struct {
		name_t src, dst;
		pgn_t pgn;

		uint8_t sa, da;
	} addr;

	struct j1939_filter *filters;
	int nfilters;

	int skb_pending;
	spinlock_t lock;
	wait_queue_head_t waitq;
};

static inline struct j1939_sock *j1939_sk(const struct sock *sk)
{
	return container_of(sk, struct j1939_sock, sk);
}

/* skb_pending issues */
static inline int j1939_sock_pending_add_first(struct sock *sk)
{
	int saved;
	struct j1939_sock *jsk = j1939_sk(sk);

	spin_lock_bh(&jsk->lock);
	if (!jsk->skb_pending) {
		++jsk->skb_pending;
		saved = 1;
	} else
		saved = 0;
	spin_unlock_bh(&jsk->lock);
	return saved;
}

static inline void j1939_sock_pending_add(struct sock *sk)
{
	struct j1939_sock *jsk = j1939_sk(sk);

	spin_lock_bh(&jsk->lock);
	++jsk->skb_pending;
	spin_unlock_bh(&jsk->lock);
}

void j1939_sock_pending_del(struct sock *sk)
{
	struct j1939_sock *jsk = j1939_sk(sk);
	int saved;

	spin_lock_bh(&jsk->lock);
	--jsk->skb_pending;
	saved = jsk->skb_pending;
	spin_unlock_bh(&jsk->lock);
	if (!saved)
		wake_up(&jsk->waitq);
}


static inline int j1939_no_address(const struct sock *sk)
{
	const struct j1939_sock *jsk = j1939_sk(sk);
	return (jsk->addr.sa == J1939_NO_ADDR) && !jsk->addr.src;
}

/*
 * list of sockets
 */
static struct {
	struct mutex lock;
	struct list_head socks;
} s;

/* matches skb control buffer (addr) with a j1939 filter */
static inline int packet_match(const struct j1939_sk_buff_cb *cb,
		const struct j1939_filter *f, int nfilter)
{
	if (!nfilter)
		/* receive all when no filters are assigned */
		return 1;
	/*
	 * Filters relying on the addr for static addressing _should_ get
	 * packets from dynamic addressed ECU's too if they match their SA.
	 * Sockets using dynamic addressing in their filters should not set it.
	 */
	for (; nfilter; ++f, --nfilter) {
		if ((cb->pgn & f->pgn_mask) != (f->pgn & f->pgn_mask))
			continue;
		if ((cb->src.addr & f->addr_mask) != (f->addr & f->addr_mask))
			continue;
		if ((cb->src.name & f->name_mask) != (f->name & f->name_mask))
			continue;
		return 1;
	}
	return 0;
}

/*
 * callback per socket, called from filter infrastructure
 */
static void j1939sk_recv_skb(struct sk_buff *oskb, void *data)
{
	struct sk_buff *skb;
	struct j1939_sock *jsk = (struct j1939_sock *)data;
	struct j1939_sk_buff_cb *cb = (void *)oskb->cb;

	if (jsk->sk.sk_bound_dev_if && (jsk->sk.sk_bound_dev_if != cb->ifindex))
		/* this socket does not take packets from this iface */
		return;
	if (!(jsk->state & PROMISC)) {
		if (cb->dst.flags & ECUFLAG_REMOTE)
			/*
			 * this msg was destined for an ECU associated
			 * with this socket
			 */
			return;
		if (jsk->addr.src) {
			if (cb->dst.name &&
				(cb->dst.name != jsk->addr.src))
				/*
				 * the msg is not destined for the name
				 * that the socket is bound to
				 */
				return;
		} else if (j1939_address_is_unicast(jsk->addr.sa)) {
			if (j1939_address_is_unicast(cb->dst.addr) &&
				(cb->dst.addr != jsk->addr.sa))
				/*
				 * the msg is not destined for the name
				 * that the socket is bound to
				 */
				return;
		}
	}

	if ((oskb->sk == &jsk->sk) && !(jsk->state & RECV_OWN))
		/* own message */
		return;

	if (!packet_match(cb, jsk->filters, jsk->nfilters))
		return;

	skb = skb_clone(oskb, GFP_ATOMIC);
	if (!skb) {
		j1939_warning("skb clone failed\n");
		return;
	}
	cb = (void *)skb->cb;
	cb->msg_flags &= ~(MSG_DONTROUTE | MSG_CONFIRM);
	if (oskb->sk)
		cb->msg_flags |= MSG_DONTROUTE;
	if (oskb->sk == &jsk->sk)
		cb->msg_flags |= MSG_CONFIRM;

	skb->sk = &jsk->sk;
	if (sock_queue_rcv_skb(&jsk->sk, skb) < 0)
		kfree_skb(skb);
}

static int j1939sk_init(struct sock *sk)
{
	struct j1939_sock *jsk = j1939_sk(sk);

	INIT_LIST_HEAD(&jsk->list);
	spin_lock_init(&jsk->lock);
	init_waitqueue_head(&jsk->waitq);
	jsk->sk.sk_priority = j1939_to_sk_priority(6);
	jsk->sk.sk_reuse = 1; /* per default */
	jsk->addr.sa = J1939_NO_ADDR;
	jsk->addr.da = J1939_NO_ADDR;
	return 0;
}

/*
 * helper: return <0 for error, >0 for error to notify
 */
static int j1939sk_bind_netdev_helper(struct socket *sock)
{
	struct j1939_sock *jsk = j1939_sk(sock->sk);
	int ret;
	struct net_device *netdev;
	struct j1939_segment *jseg;

	if (!jsk->sk.sk_bound_dev_if)
		return 0;
	ret = 0;

	netdev = dev_get_by_index(&init_net, jsk->sk.sk_bound_dev_if);
	if (!netdev) {
		ret = -ENODEV;
		goto fail_netdev;
	}

	/* no need to test for CAN device,
	 * implicitely done by j1939_segment
	 */
	jseg = j1939_segment_find(netdev->ifindex);
	if (!jseg) {
		ret = -EHOSTDOWN;
		goto fail_segment;
	}

	if (!(netdev->flags & IFF_UP)) {
		sock->sk->sk_err = ENETDOWN;
		sock->sk->sk_error_report(sock->sk);
	}
	put_j1939_segment(jseg);
fail_segment:
	dev_put(netdev);
fail_netdev:
	return ret;
}

static int j1939sk_bind_addr_helper(int ifindex, uint8_t addr)
{
	struct j1939_segment *jseg;
	struct addr_ent *paddr;
	int flags;

	/* static addressing, netdev is required */
	if (!ifindex)
		return -EINVAL;

	jseg = j1939_segment_find(ifindex);
	if (!jseg)
		return -ENETUNREACH;
	paddr = &jseg->ents[addr];
	read_lock_bh(&jseg->lock);
	flags = paddr->flags;
	read_unlock_bh(&jseg->lock);
	put_j1939_segment(jseg);
	if (!(flags & ECUFLAG_LOCAL))
		return -EADDRNOTAVAIL;
	return 0;
}

static int j1939sk_bind(struct socket *sock, struct sockaddr *uaddr, int len)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct j1939_sock *jsk = j1939_sk(sock->sk);
	int ret, old_state;

	if (len < required_size(can_addr.j1939, *addr))
		return -EINVAL;
	if (addr->can_family != AF_CAN)
		return -EINVAL;

	/* lock s.lock first, to avoid circular lock dependancy */
	mutex_lock(&s.lock);
	lock_sock(sock->sk);
	if (jsk->state & JSK_BOUND) {
		ret = -EBUSY;
		if (addr->can_ifindex &&
				(addr->can_ifindex != jsk->sk.sk_bound_dev_if))
			goto fail_locked;
		if (jsk->addr.src &&
				(jsk->addr.src == addr->can_addr.j1939.name)) {
			/*
			 * allow to change the address after the first bind()
			 * when using dynamic addressing
			 */
			/* set to be able to send address claims */
			jsk->addr.sa = addr->can_addr.j1939.addr;
		} else if (jsk->addr.sa == addr->can_addr.j1939.addr) {
			/* no change */
		} else if (j1939_address_is_unicast(addr->can_addr.j1939.addr)) {
			/* change of static source address */
			ret = j1939sk_bind_addr_helper(jsk->sk.sk_bound_dev_if,
					addr->can_addr.j1939.addr);
			if (ret < 0)
				goto fail_locked;
			jsk->addr.sa = addr->can_addr.j1939.addr;
		} else {
			goto fail_locked;
		}
		/* set default transmit pgn */
		jsk->addr.pgn = addr->can_addr.j1939.pgn;
		/* since this socket is bound already, we can skip a lot */
		release_sock(sock->sk);
		mutex_unlock(&s.lock);
		return 0;
	}

	/* do netdev */
	if (jsk->sk.sk_bound_dev_if && addr->can_ifindex &&
			(jsk->sk.sk_bound_dev_if != addr->can_ifindex)) {
		ret = -EBADR;
		goto fail_locked;
	}
	if (!jsk->sk.sk_bound_dev_if)
		jsk->sk.sk_bound_dev_if = addr->can_ifindex;

	ret = j1939sk_bind_netdev_helper(sock);
	if (ret < 0)
		goto fail_locked;

	/* bind name/addr */
	if (addr->can_addr.j1939.name) {
		struct j1939_ecu *ecu;

		ecu = j1939_ecu_find_by_name(addr->can_addr.j1939.name,
				jsk->sk.sk_bound_dev_if);
		if (!ecu || IS_ERR(ecu)) {
			ret = -EADDRNOTAVAIL;
			goto fail_locked;
		} else if (ecu->flags & ECUFLAG_REMOTE) {
			ret = -EREMOTE;
			put_j1939_ecu(ecu);
			goto fail_locked;
		} else if (jsk->sk.sk_bound_dev_if != ecu->parent->ifindex) {
			ret = -EHOSTUNREACH;
			put_j1939_ecu(ecu);
			goto fail_locked;
		}
		jsk->addr.src = ecu->name;
		jsk->addr.sa = addr->can_addr.j1939.addr;
		put_j1939_ecu(ecu);
	} else if (j1939_address_is_unicast(addr->can_addr.j1939.addr)) {
		ret = j1939sk_bind_addr_helper(jsk->sk.sk_bound_dev_if,
				addr->can_addr.j1939.addr);
		if (ret < 0)
			goto fail_locked;
		jsk->addr.sa = addr->can_addr.j1939.addr;
	} else if (addr->can_addr.j1939.addr == J1939_IDLE_ADDR) {
		/* static addressing, netdev is required */
		if (!jsk->sk.sk_bound_dev_if) {
			ret = -EINVAL;
			goto fail_locked;
		}
		jsk->addr.sa = addr->can_addr.j1939.addr;
	} else {
		/* no name, no addr */
	}

	/* set default transmit pgn */
	jsk->addr.pgn = addr->can_addr.j1939.pgn;

	old_state = jsk->state;
	jsk->state |= JSK_BOUND;

	if (!(old_state & (JSK_BOUND | JSK_CONNECTED))) {
		list_add_tail(&jsk->list, &s.socks);
		j1939_recv_add(jsk, j1939sk_recv_skb);
	}

	ret = 0;

fail_locked:
	release_sock(sock->sk);
	mutex_unlock(&s.lock);
	return ret;
}

static int j1939sk_connect(struct socket *sock, struct sockaddr *uaddr,
		int len, int flags)
{
	int ret, old_state;
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct j1939_sock *jsk = j1939_sk(sock->sk);
	struct j1939_ecu *ecu;
	int ifindex;

	if (!uaddr)
		return -EDESTADDRREQ;

	if (len < required_size(can_addr.j1939, *addr))
		return -EINVAL;
	if (addr->can_family != AF_CAN)
		return -EINVAL;

	mutex_lock(&s.lock);
	lock_sock(sock->sk);
	if (jsk->state & JSK_CONNECTED) {
		ret = -EISCONN;
		goto fail_locked;
	}

	ifindex = jsk->sk.sk_bound_dev_if;
	if (ifindex && addr->can_ifindex && (ifindex != addr->can_ifindex)) {
		ret = -ECONNREFUSED;
		goto fail_locked;
	}
	if (!ifindex)
		ifindex = addr->can_ifindex;

	/* lookup destination */
	if (addr->can_addr.j1939.name) {
		ecu = j1939_ecu_find_by_name(addr->can_addr.j1939.name,
				ifindex);
		if (!ecu) {
			ret = -EADDRNOTAVAIL;
			goto fail_locked;
		}
		if (ifindex && (ifindex != ecu->parent->ifindex)) {
			ret = -EHOSTUNREACH;
			goto fail_locked;
		}
		ifindex = ecu->parent->ifindex;
		jsk->addr.dst = ecu->name;
		jsk->addr.da = ecu->sa;
		put_j1939_ecu(ecu);
	} else {
		/* broadcast */
		jsk->addr.dst = 0;
		jsk->addr.da = addr->can_addr.j1939.addr;
	}
	/*
	 * take a default source when not present, so connected sockets
	 * will stick to the same source ECU
	 */
	if (!jsk->addr.src && !j1939_address_is_valid(jsk->addr.sa)) {
		ecu = j1939_ecu_find_segment_default_tx(ifindex,
				&jsk->addr.src, &jsk->addr.sa);
		if (IS_ERR(ecu)) {
			ret = PTR_ERR(ecu);
			goto fail_locked;
		}
		put_j1939_ecu(ecu);
	}

	/* start assigning, no problem can occur at this point anymore */
	jsk->sk.sk_bound_dev_if = ifindex;

	if (!(jsk->state & JSK_BOUND) || !pgn_is_valid(jsk->addr.pgn)) {
		/*
		 * bind() takes precedence over connect() for the
		 * pgn to use ourselve
		 */
		jsk->addr.pgn = addr->can_addr.j1939.pgn;
	}

	old_state = jsk->state;
	jsk->state |= JSK_CONNECTED;

	if (!(old_state & (JSK_BOUND | JSK_CONNECTED))) {
		list_add_tail(&jsk->list, &s.socks);
		j1939_recv_add(jsk, j1939sk_recv_skb);
	}
	release_sock(sock->sk);
	mutex_unlock(&s.lock);
	return 0;

fail_locked:
	release_sock(sock->sk);
	mutex_unlock(&s.lock);
	return ret;
}

static void j1939sk_sock2sockaddr_can(struct sockaddr_can *addr,
		const struct j1939_sock *jsk, int peer)
{
	addr->can_family = AF_CAN;
	addr->can_ifindex = jsk->sk.sk_bound_dev_if;
	addr->can_addr.j1939.name = peer ? jsk->addr.dst : jsk->addr.src;
	addr->can_addr.j1939.pgn = jsk->addr.pgn;
	addr->can_addr.j1939.addr = peer ? jsk->addr.da : jsk->addr.sa;
}

static int j1939sk_getname(struct socket *sock, struct sockaddr *uaddr,
		int *len, int peer)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct j1939_sock *jsk = j1939_sk(sk);
	int ret = 0;

	lock_sock(sk);

	if (peer && !(jsk->state & JSK_CONNECTED)) {
		ret = -EADDRNOTAVAIL;
		goto failure;
	}

	j1939sk_sock2sockaddr_can(addr, jsk, peer);
	*len = sizeof(*addr);

failure:
	release_sock(sk);

	return ret;
}

static int j1939sk_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct j1939_sock *jsk;

	if (!sk)
		return 0;
	jsk = j1939_sk(sk);
	j1939_recv_remove(jsk, j1939sk_recv_skb);
	mutex_lock(&s.lock);
	list_del_init(&jsk->list);
	mutex_unlock(&s.lock);

	lock_sock(sk);
	if (jsk->state & PROMISC)
		j1939_put_promisc_receiver(jsk->sk.sk_bound_dev_if);

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return 0;
}

static int j1939sk_setsockopt_flag(struct j1939_sock *jsk,
		char __user *optval, unsigned int optlen, int flag)
{
	int tmp;

	if (optlen != sizeof(tmp))
		return -EINVAL;
	if (copy_from_user(&tmp, optval, optlen))
		return -EFAULT;
	lock_sock(&jsk->sk);
	if (tmp)
		jsk->state |= flag;
	else
		jsk->state &= ~flag;
	release_sock(&jsk->sk);
	return tmp;
}

static int j1939sk_setsockopt(struct socket *sock, int level, int optname,
		char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct j1939_sock *jsk = j1939_sk(sk);
	int ret = 0, tmp, count;
	struct j1939_filter *filters, *ofilters;

	if (level != SOL_CAN_J1939)
		return -EINVAL;

	switch (optname) {
	case SO_J1939_FILTER:
		if (optval) {
			if (optlen % sizeof(*filters) != 0)
				return -EINVAL;
			count = optlen / sizeof(*filters);
			filters = kmalloc(optlen, GFP_KERNEL);
			if (!filters)
				return -ENOMEM;
			if (copy_from_user(filters, optval, optlen)) {
				kfree(filters);
				return -EFAULT;
			}
		} else {
			filters = NULL;
			count = 0;
		}

		j1939_recv_suspend();
		ofilters = jsk->filters;
		jsk->filters = filters;
		jsk->nfilters = count;
		j1939_recv_resume();
		if (ofilters)
			kfree(ofilters);
		break;
	case SO_J1939_PROMISC:
		tmp = jsk->state & PROMISC;
		ret = j1939sk_setsockopt_flag(jsk, optval, optlen, PROMISC);
		if (ret && !tmp)
			j1939_get_promisc_receiver(jsk->sk.sk_bound_dev_if);
		else if (!ret && tmp)
			j1939_put_promisc_receiver(jsk->sk.sk_bound_dev_if);
		ret = 0;
		break;
	case SO_J1939_RECV_OWN:
		j1939sk_setsockopt_flag(jsk, optval, optlen, RECV_OWN);
		break;
	case SO_J1939_SEND_PRIO:
		if (optlen != sizeof(tmp))
			return -EINVAL;
		if (copy_from_user(&tmp, optval, optlen))
			return -EFAULT;
		if ((tmp < 0) || (tmp > 7))
			return -EDOM;
		if ((tmp < 2) && !capable(CAP_NET_ADMIN))
			return -EPERM;
		lock_sock(&jsk->sk);
		jsk->sk.sk_priority = j1939_to_sk_priority(tmp);
		release_sock(&jsk->sk);
		break;
	default:
		return -ENOPROTOOPT;
	}

	return ret;
}

static int j1939sk_getsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct j1939_sock *jsk = j1939_sk(sk);
	int ret, ulen;
	/* set defaults for using 'int' properties */
	int tmp = 0;
	int len = sizeof(tmp);
	void *val = &tmp;

	if (level != SOL_CAN_J1939)
		return -EINVAL;
	if (get_user(ulen, optlen))
		return -EFAULT;
	if (ulen < 0)
		return -EINVAL;

	lock_sock(&jsk->sk);
	switch (optname) {
	case SO_J1939_PROMISC:
		tmp = (jsk->state & PROMISC) ? 1 : 0;
		break;
	case SO_J1939_RECV_OWN:
		tmp = (jsk->state & RECV_OWN) ? 1 : 0;
		break;
	case SO_J1939_SEND_PRIO:
		tmp = j1939_prio(jsk->sk.sk_priority);
		break;
	default:
		ret = -ENOPROTOOPT;
		goto no_copy;
	}

	/*
	 * copy to user, based on 'len' & 'val'
	 * but most sockopt's are 'int' properties, and have 'len' & 'val'
	 * left unchanged, but instead modified 'tmp'
	 */
	if (len > ulen)
		ret = -EFAULT;
	else if (put_user(len, optlen))
		ret = -EFAULT;
	else if (copy_to_user(optval, val, len))
		ret = -EFAULT;
	else
		ret = 0;
no_copy:
	release_sock(&jsk->sk);
	return ret;
}

static int j1939sk_recvmsg(struct kiocb *iocb, struct socket *sock,
			 struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	struct j1939_sk_buff_cb *sk_addr;
	int ret = 0;

	skb = skb_recv_datagram(sk, flags, 0, &ret);
	if (!skb)
		return ret;

	if (size < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	else
		size = skb->len;

	ret = memcpy_toiovec(msg->msg_iov, skb->data, size);
	if (ret < 0)
		goto failed_with_skb;

	sock_recv_timestamp(msg, sk, skb);
	sk_addr = (void *)skb->cb;

	if (j1939_address_is_valid(sk_addr->dst.addr))
		put_cmsg(msg, SOL_CAN_J1939, SCM_J1939_DEST_ADDR,
				sizeof(sk_addr->dst.addr), &sk_addr->dst.addr);

	if (sk_addr->dst.name)
		put_cmsg(msg, SOL_CAN_J1939, SCM_J1939_DEST_NAME,
				sizeof(sk_addr->dst.name), &sk_addr->dst.name);

	put_cmsg(msg, SOL_CAN_J1939, SCM_J1939_PRIO,
			sizeof(sk_addr->priority), &sk_addr->priority);

	if (msg->msg_name) {
		struct sockaddr_can *paddr = msg->msg_name;

		msg->msg_namelen = required_size(can_addr.j1939, *paddr);
		memset(msg->msg_name, 0, msg->msg_namelen);
		paddr->can_family = AF_CAN;
		paddr->can_ifindex = sk_addr->ifindex;
		paddr->can_addr.j1939.name = sk_addr->src.name;
		paddr->can_addr.j1939.addr = sk_addr->src.addr;
		paddr->can_addr.j1939.pgn = sk_addr->pgn;
	}

	msg->msg_flags |= sk_addr->msg_flags;
	skb_free_datagram(sk, skb);

	return size;

failed_with_skb:
	skb_kill_datagram(sk, skb, flags);
	return ret;
}

static int j1939sk_sendmsg(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct j1939_sock *jsk = j1939_sk(sk);
	struct j1939_sk_buff_cb *skb_cb;
	struct sk_buff *skb;
	struct net_device *dev;
	struct j1939_ecu *ecu;
	int ifindex;
	int ret;

	if (!(jsk->state & JSK_BOUND))
		return -ENOTCONN;

	if (msg->msg_name && (msg->msg_namelen <
			required_size(can_addr.j1939, struct sockaddr_can)))
		return -EINVAL;

	ifindex = jsk->sk.sk_bound_dev_if;
	if (msg->msg_name) {
		struct sockaddr_can *addr = msg->msg_name;
		if (msg->msg_namelen < required_size(can_addr.j1939, *addr))
			return -EFAULT;
		if (addr->can_family != AF_CAN)
			return -EINVAL;
		if (ifindex && addr->can_ifindex &&
			(ifindex != addr->can_ifindex))
			return -ENONET;
		if (!ifindex)
			/* take destination intf when intf not yet set */
			ifindex = addr->can_ifindex;
	}

	if (!ifindex)
		return -EDESTADDRREQ;
	if (j1939_no_address(&jsk->sk)) {
		lock_sock(&jsk->sk);
		ecu = j1939_ecu_find_segment_default_tx(
				jsk->sk.sk_bound_dev_if,
				&jsk->addr.src, &jsk->addr.sa);
		release_sock(&jsk->sk);
		if (IS_ERR(ecu))
			return PTR_ERR(ecu);
	}

	dev = dev_get_by_index(&init_net, ifindex);
	if (!dev)
		return -ENXIO;

	skb = sock_alloc_send_skb(sk, size,
			msg->msg_flags & MSG_DONTWAIT, &ret);
	if (!skb)
		goto put_dev;

	ret = memcpy_fromiovec(skb_put(skb, size), msg->msg_iov, size);
	if (ret < 0)
		goto free_skb;
	skb->dev = dev;
	skb->sk  = sk;

	BUILD_BUG_ON(sizeof(skb->cb) < sizeof(*skb_cb));

	skb_cb = (void *) skb->cb;
	memset(skb_cb, 0, sizeof(*skb_cb));
	skb_cb->msg_flags = msg->msg_flags;
	skb_cb->ifindex = ifindex;
	skb_cb->src.name = jsk->addr.src;
	skb_cb->dst.name = jsk->addr.dst;
	skb_cb->pgn = jsk->addr.pgn;
	skb_cb->priority = j1939_prio(jsk->sk.sk_priority);
	skb_cb->src.addr = jsk->addr.sa;
	skb_cb->dst.addr = jsk->addr.da;

	if (msg->msg_name) {
		struct sockaddr_can *addr = msg->msg_name;
		if (addr->can_addr.j1939.name) {
			ecu = j1939_ecu_find_by_name(addr->can_addr.j1939.name,
					ifindex);
			if (!ecu)
				return -EADDRNOTAVAIL;
			skb_cb->dst.name = ecu->name;
			skb_cb->dst.addr = ecu->sa;
			put_j1939_ecu(ecu);
		} else {
			skb_cb->dst.name = 0;
			skb_cb->dst.addr = addr->can_addr.j1939.addr;
		}
		if (pgn_is_valid(addr->can_addr.j1939.pgn))
			skb_cb->pgn = addr->can_addr.j1939.pgn;
	}

	if (skb_cb->msg_flags & J1939_MSG_SYNC) {
		if (skb_cb->msg_flags & MSG_DONTWAIT) {
			ret = j1939_sock_pending_add_first(&jsk->sk);
			if (ret > 0)
				ret = -EAGAIN;
		} else {
			ret = wait_event_interruptible(jsk->waitq,
					j1939_sock_pending_add_first(&jsk->sk));
		}
		if (ret < 0)
			goto free_skb;
	} else {
		j1939_sock_pending_add(&jsk->sk);
	}

	ret = j1939_send(skb, j1939_level_sky);
	if (ret < 0)
		goto decrement_pending;

	dev_put(dev);
	return size;

decrement_pending:
	j1939_sock_pending_del(&jsk->sk);
free_skb:
	kfree_skb(skb);
put_dev:
	dev_put(dev);
	return ret;
}

/* PROC */
static int j1939sk_proc_show(struct seq_file *sqf, void *v)
{
	struct j1939_sock *jsk;
	struct net_device *netdev;

	seq_printf(sqf, "iface\tflags\tlocal\tremote\tpgn\tprio\tpending\n");
	mutex_lock(&s.lock);
	list_for_each_entry(jsk, &s.socks, list) {
		lock_sock(&jsk->sk);
		netdev = NULL;
		if (jsk->sk.sk_bound_dev_if)
			netdev = dev_get_by_index(&init_net,
				jsk->sk.sk_bound_dev_if);
		seq_printf(sqf, "%s\t", netdev ? netdev->name : "-");
		if (netdev)
			dev_put(netdev);
		seq_printf(sqf, "%c%c%c%c\t",
			(jsk->state & JSK_BOUND) ? 'b' : '-',
			(jsk->state & JSK_CONNECTED) ? 'c' : '-',
			(jsk->state & PROMISC) ? 'P' : '-',
			(jsk->state & RECV_OWN) ? 'o' : '-');
		if (jsk->addr.src)
			seq_printf(sqf, "%016llx", (long long)jsk->addr.src);
		else if (j1939_address_is_unicast(jsk->addr.sa))
			seq_printf(sqf, "%02x", jsk->addr.sa);
		else
			seq_printf(sqf, "-");
		seq_printf(sqf, "\t");
		if (jsk->addr.dst)
			seq_printf(sqf, "%016llx", (long long)jsk->addr.dst);
		else if (j1939_address_is_unicast(jsk->addr.da))
			seq_printf(sqf, "%02x", jsk->addr.da);
		else
			seq_printf(sqf, "-");
		seq_printf(sqf, "\t%05x", jsk->addr.pgn);
		seq_printf(sqf, "\t%u", j1939_prio(jsk->sk.sk_priority));
		seq_printf(sqf, "\t%u", jsk->skb_pending);
		release_sock(&jsk->sk);
		seq_printf(sqf, "\n");
	}
	mutex_unlock(&s.lock);
	return 0;
}

void j1939sk_netdev_event(int ifindex, int error_code)
{
	struct j1939_sock *jsk;

	mutex_lock(&s.lock);
	list_for_each_entry(jsk, &s.socks, list) {
		if (jsk->sk.sk_bound_dev_if != ifindex)
			continue;
		jsk->sk.sk_err = error_code;
		if (!sock_flag(&jsk->sk, SOCK_DEAD))
			jsk->sk.sk_error_report(&jsk->sk);
		/* do not remove filters here */
	}
	mutex_unlock(&s.lock);
}

static const struct proto_ops j1939_ops = {
	.family = PF_CAN,
	.release = j1939sk_release,
	.bind = j1939sk_bind,
	.connect = j1939sk_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = j1939sk_getname,
	.poll = datagram_poll,
	.ioctl = can_ioctl,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = j1939sk_setsockopt,
	.getsockopt = j1939sk_getsockopt,
	.sendmsg = j1939sk_sendmsg,
	.recvmsg = j1939sk_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static struct proto j1939_proto __read_mostly = {
	.name = "CAN_J1939",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct j1939_sock),
	.init = j1939sk_init,
};

static const struct can_proto j1939_can_proto = {
	.type = SOCK_DGRAM,
	.protocol = CAN_J1939,
	.ops = &j1939_ops,
	.prot = &j1939_proto,

	.rtnl_link_ops = &j1939_rtnl_af_ops,
	.rtnl_new_addr = j1939rtnl_new_addr,
	.rtnl_del_addr = j1939rtnl_del_addr,
	.rtnl_dump_addr = j1939rtnl_dump_addr,
};

__init int j1939sk_module_init(void)
{
	int ret;

	INIT_LIST_HEAD(&s.socks);
	mutex_init(&s.lock);

	ret = can_proto_register(&j1939_can_proto);
	if (ret < 0)
		pr_err("can: registration of j1939 protocol failed\n");
	else
		j1939_proc_add("sock", j1939sk_proc_show, NULL);
	return ret;
}

void j1939sk_module_exit(void)
{
	j1939_proc_remove("sock");
	can_proto_unregister(&j1939_can_proto);
}

MODULE_ALIAS("can-proto-" __stringify(CAN_J1939));

