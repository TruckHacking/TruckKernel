/*
 * Copyright (c) 2011 EIA Electronics
 *
 * Authors:
 * Kurt Van Dijck <kurt.van.dijck@eia.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 */

/*
 * j1939-rtnl.c - netlink addressing interface
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/if_arp.h>

#include "j1939-priv.h"

static const struct nla_policy j1939_ifa_policy[IFA_J1939_MAX] = {
	[IFA_J1939_ADDR] = { .type = NLA_U8, },
	[IFA_J1939_NAME] = { .type = NLA_U64, },
};

int j1939rtnl_del_addr(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	int ret;
	struct ifaddrmsg *ifm;
	struct j1939_segment *jseg;
	uint8_t jaddr = J1939_NO_ADDR;
	uint64_t jname = J1939_NO_NAME;

	struct nlattr *nla, *tb[IFA_J1939_MAX];

	if (!net_eq(sock_net(skb->sk), &init_net))
		return -EINVAL;

	nla = nlmsg_find_attr(nlh, sizeof(*ifm), IFA_LOCAL);
	if (!nla)
		return -EINVAL;

	nla_parse_nested(tb, IFA_J1939_MAX-1, nla, j1939_ifa_policy);
	if (tb[IFA_J1939_ADDR])
		jaddr = nla_get_u8(tb[IFA_J1939_ADDR]);
	if (tb[IFA_J1939_NAME])
		jname = be64_to_cpu(nla_get_u64(tb[IFA_J1939_NAME]));

	ifm = nlmsg_data(nlh);
	jseg = j1939_segment_find(ifm->ifa_index);
	if (!jseg)
		return -EHOSTDOWN;

	ret = 0;
	if (j1939_address_is_unicast(jaddr)) {
		struct addr_ent *ent;

		ent = &jseg->ents[jaddr];
		write_lock_bh(&jseg->lock);
		if (!ent->flags)
			ret = -EADDRNOTAVAIL;
		else if (!(ent->flags & ECUFLAG_LOCAL))
			ret = -EREMOTE;
		else
			ent->flags = 0;
		write_unlock_bh(&jseg->lock);
	} else if (jname) {
		struct j1939_ecu *ecu;

		ecu = j1939_ecu_find_by_name(jname, ifm->ifa_index);
		if (ecu) {
			if (ecu->flags & ECUFLAG_LOCAL) {
				j1939_ecu_unregister(ecu);
				put_j1939_ecu(ecu);
			} else {
				ret = -EREMOTE;
			}
		} else {
			ret = -ENODEV;
		}
	}
	put_j1939_segment(jseg);
	return ret;
}

int j1939rtnl_new_addr(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct ifaddrmsg *ifm;
	struct j1939_segment *jseg;
	uint8_t jaddr = J1939_NO_ADDR;
	uint64_t jname = J1939_NO_NAME;
	struct addr_ent *ent;
	int ret;
	struct nlattr *nla, *tb[IFA_J1939_MAX];

	if (!net_eq(sock_net(skb->sk), &init_net))
		return -EINVAL;

	nla = nlmsg_find_attr(nlh, sizeof(*ifm), IFA_LOCAL);
	if (!nla)
		return -EINVAL;

	ifm = nlmsg_data(nlh);
	jseg = j1939_segment_find(ifm->ifa_index);
	if (!jseg)
		return -EHOSTDOWN;

	nla_parse_nested(tb, IFA_J1939_MAX-1, nla, j1939_ifa_policy);
	if (tb[IFA_J1939_ADDR])
		jaddr = nla_get_u8(tb[IFA_J1939_ADDR]);
	if (tb[IFA_J1939_NAME])
		jname = be64_to_cpu(nla_get_u64(tb[IFA_J1939_NAME]));

	ret = 0;
	if (j1939_address_is_unicast(jaddr)) {
		ent = &jseg->ents[jaddr];
		write_lock_bh(&jseg->lock);
		if ((ent->ecu && (ent->ecu->flags & ECUFLAG_REMOTE)) ||
				(ent->flags & ECUFLAG_REMOTE))
			ret = -EREMOTE;
		else
			ent->flags |= ECUFLAG_LOCAL;
		write_unlock_bh(&jseg->lock);
	} else if (jname) {
		struct j1939_ecu *ecu;

		ecu = j1939_ecu_get_register(jname, ifm->ifa_index,
				ECUFLAG_LOCAL, 0);
		if (IS_ERR(ecu))
			ret = PTR_ERR(ecu);
		else
			put_j1939_ecu(ecu);
	}
	put_j1939_segment(jseg);
	return ret;
}

static int j1939rtnl_fill_ifaddr(struct sk_buff *skb, int ifindex,
		uint8_t addr, uint64_t name, int j1939_flags,
		u32 pid, u32 seq, int event, unsigned int flags)
{
	struct ifaddrmsg *ifm;
	struct nlmsghdr *nlh;
	struct nlattr *nla;

	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*ifm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ifm = nlmsg_data(nlh);
	ifm->ifa_family = AF_CAN;
	ifm->ifa_prefixlen = CAN_J1939;
	ifm->ifa_flags = name ? 0 : IFA_F_PERMANENT;
	ifm->ifa_scope = RT_SCOPE_LINK;
	ifm->ifa_index = ifindex;

	nla = nla_nest_start(skb, IFA_LOCAL);
	if (j1939_address_is_unicast(addr))
		if (nla_put_u8(skb, IFA_J1939_ADDR, addr) < 0)
			goto nla_failure;
	if (name)
		if (nla_put_u64(skb, IFA_J1939_NAME, cpu_to_be64(name)) < 0)
			goto nla_failure;
	nla_nest_end(skb, nla);

	return nlmsg_end(skb, nlh);
nla_failure:
       nlmsg_cancel(skb, nlh);
       return -EMSGSIZE;
}

int j1939rtnl_dump_addr(struct sk_buff *skb, struct netlink_callback *cb)
{
	int ndev, addr, ret, sa;
	struct net_device *netdev;
	struct j1939_segment *jseg;
	struct j1939_ecu *ecu;
	struct addr_ent *ent;

	if (!net_eq(sock_net(skb->sk), &init_net))
		return 0;

	ndev = 0;
	for_each_netdev(&init_net, netdev) {
		++ndev;
		if (ndev < cb->args[1])
			continue;
		if (netdev->type != ARPHRD_CAN)
			continue;

		jseg = j1939_segment_find(netdev->ifindex);
		if (!jseg)
			continue;

		read_lock_bh(&jseg->lock);
		for (addr = cb->args[2]; addr < J1939_IDLE_ADDR; ++addr) {
			ent = &jseg->ents[addr];
			if (!(ent->flags & ECUFLAG_LOCAL))
				continue;
			ret = j1939rtnl_fill_ifaddr(skb, netdev->ifindex, addr,
					0, ent->flags, NETLINK_CB(cb->skb).pid,
					cb->nlh->nlmsg_seq, RTM_NEWADDR,
					NLM_F_MULTI);
			if (ret < 0) {
				read_unlock_bh(&jseg->lock);
				goto done;
			}
			cb->args[2] = addr + 1;
		}

		if (addr > J1939_IDLE_ADDR)
			addr = J1939_IDLE_ADDR;
		list_for_each_entry(ecu, &jseg->ecus, list) {
			if (addr++ < cb->args[2])
				continue;
			if (!(ecu->flags & ECUFLAG_LOCAL))
				continue;
			sa = ecu->sa;
			if (ecu->parent->ents[sa].ecu != ecu)
				sa = J1939_IDLE_ADDR;
			ret = j1939rtnl_fill_ifaddr(skb, netdev->ifindex,
					sa, ecu->name, ecu->flags,
					NETLINK_CB(cb->skb).pid,
					cb->nlh->nlmsg_seq, RTM_NEWADDR,
					NLM_F_MULTI);
			if (ret < 0) {
				read_unlock_bh(&jseg->lock);
				goto done;
			}
			cb->args[2] = addr;
		}
		read_unlock_bh(&jseg->lock);
		/* reset first address for device */
		cb->args[2] = 0;
	}
	++ndev;
done:
	cb->args[1] = ndev;

	return skb->len;
}

/*
 * rtnl_link_ops
 */

static const struct nla_policy j1939_ifla_policy[IFLA_J1939_MAX] = {
	[IFLA_J1939_ENABLE] = { .type = NLA_U8, },
};

static size_t j1939_get_link_af_size(const struct net_device *dev)
{
	return nla_policy_len(j1939_ifla_policy, IFLA_J1939_MAX-1);
}

static int j1939_validate_link_af(const struct net_device *dev,
				 const struct nlattr *nla)
{
	return nla_validate_nested(nla, IFLA_J1939_MAX-1, j1939_ifla_policy);
}

static int j1939_fill_link_af(struct sk_buff *skb, const struct net_device *dev)
{
	struct j1939_segment *jseg;

	if (!dev)
		return -ENODEV;
	jseg = j1939_segment_find(dev->ifindex);
	if (jseg)
		put_j1939_segment(jseg);
	if (nla_put_u8(skb, IFLA_J1939_ENABLE, jseg ? 1 : 0) < 0)
		return -EMSGSIZE;
	return 0;
}

static int j1939_set_link_af(struct net_device *dev, const struct nlattr *nla)
{
	int ret;
	struct nlattr *tb[IFLA_J1939_MAX];

	ret = nla_parse_nested(tb, IFLA_J1939_MAX-1, nla, j1939_ifla_policy);
	if (ret < 0)
		return ret;

	if (tb[IFLA_J1939_ENABLE]) {
		if (nla_get_u8(tb[IFLA_J1939_ENABLE]))
			ret = j1939_segment_attach(dev);
		else
			ret = j1939_segment_detach(dev);
		if (ret < 0)
			return ret;
	}
	return 0;
}

const struct rtnl_af_ops j1939_rtnl_af_ops = {
	.family		  = AF_CAN,
	.fill_link_af	  = j1939_fill_link_af,
	.get_link_af_size = j1939_get_link_af_size,
	.validate_link_af = j1939_validate_link_af,
	.set_link_af	  = j1939_set_link_af,
};

