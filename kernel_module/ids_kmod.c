// SPDX-License-Identifier: GPL-2.0
/*
 * ids_kmod.c — IDS Kernel Module
 *
 * Hooks NF_INET_PRE_ROUTING, extracts 5-tuple from sk_buff,
 * and forwards packet descriptors to userspace via Generic Netlink.
 *
 * Build:  make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 * Load:   sudo insmod ids_kmod.ko
 * Unload: sudo rmmod ids_kmod
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/ktime.h>
#include <net/genetlink.h>
#include "ids_kmod.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IDS Team");
MODULE_DESCRIPTION("Intrusion Detection System - Kernel Packet Interceptor");
MODULE_VERSION("1.0");

/* ── Generic Netlink family ─────────────────────────────────────────────── */

static struct genl_family ids_genl_family;

static struct genl_multicast_group ids_mcgrps[] = {
    {.name = IDS_MCAST_GROUP},
};

static struct genl_ops ids_genl_ops[] = {
    {
        .cmd = IDS_CMD_PKT_EVENT,
        .doit = NULL, /* kernel-only sender; no handler needed */
    },
};

static struct nla_policy ids_genl_policy[IDS_ATTR_MAX + 1] = {
    [IDS_ATTR_PKT] = {.type = NLA_BINARY,
                      .len = sizeof(struct ids_pkt_desc)},
};

static struct genl_family ids_genl_family = {
    .name = IDS_NETLINK_FAMILY,
    .version = IDS_NETLINK_VERSION,
    .maxattr = IDS_ATTR_MAX,
    .policy = ids_genl_policy,
    .ops = ids_genl_ops,
    .n_ops = ARRAY_SIZE(ids_genl_ops),
    .mcgrps = ids_mcgrps,
    .n_mcgrps = ARRAY_SIZE(ids_mcgrps),
    .module = THIS_MODULE,
};

/* ── Send packet descriptor to userspace ────────────────────────────────── */

static void ids_send_pkt(const struct ids_pkt_desc *desc)
{
    struct sk_buff *skb;
    void *hdr;

    skb = genlmsg_new(nla_total_size(sizeof(*desc)), GFP_ATOMIC);
    if (!skb)
        return;

    hdr = genlmsg_put(skb, 0, 0, &ids_genl_family, 0, IDS_CMD_PKT_EVENT);
    if (!hdr)
    {
        nlmsg_free(skb);
        return;
    }

    if (nla_put(skb, IDS_ATTR_PKT, sizeof(*desc), desc))
    {
        genlmsg_cancel(skb, hdr);
        nlmsg_free(skb);
        return;
    }

    genlmsg_end(skb, hdr);
    /* Broadcast to all listeners in the multicast group */
    genlmsg_multicast(&ids_genl_family, skb, 0, 0, GFP_ATOMIC);
}

/* ── Netfilter hook ─────────────────────────────────────────────────────── */

static unsigned int ids_nf_hook(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct ids_pkt_desc desc = {};

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4)
        return NF_ACCEPT;

    desc.src_ip = ntohl(iph->saddr);
    desc.dst_ip = ntohl(iph->daddr);
    desc.protocol = iph->protocol;
    desc.pkt_len = ntohs(iph->tot_len);
    desc.ts_nsec = ktime_get_ns();

    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        tcph = tcp_hdr(skb);
        if (!tcph)
            break;
        desc.src_port = ntohs(tcph->source);
        desc.dst_port = ntohs(tcph->dest);
        desc.tcp_flags = ((__u8 *)tcph)[13]; /* flags byte */
        break;

    case IPPROTO_UDP:
        udph = udp_hdr(skb);
        if (!udph)
            break;
        desc.src_port = ntohs(udph->source);
        desc.dst_port = ntohs(udph->dest);
        break;

    case IPPROTO_ICMP:
        /* no ports for ICMP */
        break;

    default:
        return NF_ACCEPT; /* skip non-TCP/UDP/ICMP */
    }

    ids_send_pkt(&desc);
    return NF_ACCEPT; /* always accept — we only observe */
}

static struct nf_hook_ops ids_nf_ops = {
    .hook = ids_nf_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

/* ── Module init / exit ─────────────────────────────────────────────────── */

static int __init ids_kmod_init(void)
{
    int ret;

    ret = genl_register_family(&ids_genl_family);
    if (ret)
    {
        pr_err("ids_kmod: genl_register_family failed: %d\n", ret);
        return ret;
    }

    ret = nf_register_net_hook(&init_net, &ids_nf_ops);
    if (ret)
    {
        pr_err("ids_kmod: nf_register_net_hook failed: %d\n", ret);
        genl_unregister_family(&ids_genl_family);
        return ret;
    }

    pr_info("ids_kmod: loaded — intercepting IPv4 packets\n");
    return 0;
}

static void __exit ids_kmod_exit(void)
{
    nf_unregister_net_hook(&init_net, &ids_nf_ops);
    genl_unregister_family(&ids_genl_family);
    pr_info("ids_kmod: unloaded\n");
}

module_init(ids_kmod_init);
module_exit(ids_kmod_exit);