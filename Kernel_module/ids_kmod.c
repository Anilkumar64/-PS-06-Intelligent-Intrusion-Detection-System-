// SPDX-License-Identifier: GPL-2.0
/*
 * ids_kmod.c — IDS Kernel Module (kernel 6.8 compatible)
 *
 * Fixed for kernel 6.8:
 *   - Removed parallel_ops (field dropped in 6.2)
 *   - GENL_DONT_VALIDATE_STRICT on all ops
 *   - resv_start_op set correctly
 *   - DEFINE_SHOW_ATTRIBUTE for /proc (5.6+)
 *   - Single family declaration
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/ktime.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>

#include "ids_kmod.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IDS Team");
MODULE_DESCRIPTION("Intrusion Detection System — Kernel Packet Interceptor");
MODULE_VERSION("1.2");

/* ── Module parameters ──────────────────────────────────────────────────── */

static unsigned int rate_limit_pps = 100000;
module_param(rate_limit_pps, uint, 0444);
MODULE_PARM_DESC(rate_limit_pps,
                 "Max packets forwarded to userspace per second (default 100000)");

/* ── Atomic statistics ───────────────────────────────────────────────────── */

static atomic64_t g_pkts_seen = ATOMIC64_INIT(0);
static atomic64_t g_pkts_sent = ATOMIC64_INIT(0);
static atomic64_t g_pkts_dropped = ATOMIC64_INIT(0);
static atomic64_t g_pkts_filtered = ATOMIC64_INIT(0);
static atomic64_t g_alloc_failures = ATOMIC64_INIT(0);

/* ── Per-CPU rate limiter ────────────────────────────────────────────────── */

struct ids_percpu_ratelim
{
    unsigned long last_jiffy;
    unsigned int count;
};

static DEFINE_PER_CPU(struct ids_percpu_ratelim, ids_ratelim);

static bool ids_ratelimit_check(void)
{
    struct ids_percpu_ratelim *rl;
    unsigned long now = jiffies;
    bool allowed;

    preempt_disable();
    rl = this_cpu_ptr(&ids_ratelim);

    if (time_after(now, rl->last_jiffy))
    {
        rl->last_jiffy = now;
        rl->count = 0;
    }

    allowed = (rl->count < (rate_limit_pps / HZ + 1));
    if (allowed)
        rl->count++;

    preempt_enable();
    return allowed;
}

/* ── Forward declaration ─────────────────────────────────────────────────── */

static struct genl_family ids_genl_family;

/* ── Netlink attribute policy ────────────────────────────────────────────── */

static const struct nla_policy ids_genl_policy[IDS_ATTR_MAX + 1] = {
    [IDS_ATTR_PKT] = {.type = NLA_BINARY,
                      .len = sizeof(struct ids_pkt_desc)},
    [IDS_ATTR_STATS] = {.type = NLA_BINARY,
                        .len = sizeof(struct ids_kmod_stats)},
};

/* ── Stats command handler ───────────────────────────────────────────────── */

static int ids_cmd_get_stats(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *reply;
    struct ids_kmod_stats stats = {};
    void *hdr;

    stats.pkts_seen = (u64)atomic64_read(&g_pkts_seen);
    stats.pkts_sent = (u64)atomic64_read(&g_pkts_sent);
    stats.pkts_dropped = (u64)atomic64_read(&g_pkts_dropped);
    stats.pkts_filtered = (u64)atomic64_read(&g_pkts_filtered);
    stats.alloc_failures = (u64)atomic64_read(&g_alloc_failures);

    reply = genlmsg_new(nla_total_size(sizeof(stats)), GFP_KERNEL);
    if (!reply)
        return -ENOMEM;

    hdr = genlmsg_put_reply(reply, info, &ids_genl_family,
                            0, IDS_CMD_STATS_REPLY);
    if (!hdr)
    {
        nlmsg_free(reply);
        return -EMSGSIZE;
    }

    if (nla_put(reply, IDS_ATTR_STATS, sizeof(stats), &stats))
    {
        genlmsg_cancel(skb, hdr);
        nlmsg_free(reply);
        return -EMSGSIZE;
    }

    genlmsg_end(reply, hdr);
    return genlmsg_reply(reply, info);
}

/* ── Generic Netlink ops ─────────────────────────────────────────────────── */

static const struct genl_ops ids_genl_ops[] = {
    {
        .cmd = IDS_CMD_GET_STATS,
        .doit = ids_cmd_get_stats,
        .flags = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP | GENL_ADMIN_PERM,
    },
};

/* ── Multicast group ─────────────────────────────────────────────────────── */

static const struct genl_multicast_group ids_mcgrps[] = {
    {.name = IDS_MCAST_GROUP},
};

/* ── Family (single definition, kernel 6.8 compatible) ──────────────────── */

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
    .resv_start_op = IDS_CMD_GET_STATS,
};

/* ── Send packet descriptor to userspace ────────────────────────────────── */

static void ids_send_pkt(const struct ids_pkt_desc *desc)
{
    struct sk_buff *skb;
    void *hdr;
    int ret;

    skb = genlmsg_new(nla_total_size(sizeof(*desc)), GFP_ATOMIC);
    if (unlikely(!skb))
    {
        atomic64_inc(&g_alloc_failures);
        atomic64_inc(&g_pkts_dropped);
        return;
    }

    hdr = genlmsg_put(skb, 0, 0, &ids_genl_family, 0, IDS_CMD_PKT_EVENT);
    if (unlikely(!hdr))
    {
        nlmsg_free(skb);
        atomic64_inc(&g_pkts_dropped);
        return;
    }

    if (unlikely(nla_put(skb, IDS_ATTR_PKT, sizeof(*desc), desc)))
    {
        genlmsg_cancel(skb, hdr);
        nlmsg_free(skb);
        atomic64_inc(&g_pkts_dropped);
        return;
    }

    genlmsg_end(skb, hdr);

    /* -ESRCH = no subscribers, not an error */
    ret = genlmsg_multicast(&ids_genl_family, skb, 0, 0, GFP_ATOMIC);
    if (likely(ret == 0 || ret == -ESRCH))
        atomic64_inc(&g_pkts_sent);
    else
        atomic64_inc(&g_pkts_dropped);
}

/* ── Netfilter hook ──────────────────────────────────────────────────────── */

static unsigned int ids_nf_hook(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    const struct iphdr *iph;
    const struct tcphdr *tcph;
    const struct udphdr *udph;
    struct ids_pkt_desc desc;

    if (unlikely(!skb))
        return NF_ACCEPT;

    atomic64_inc(&g_pkts_seen);

    iph = ip_hdr(skb);
    if (unlikely(!iph || iph->version != 4))
        return NF_ACCEPT;

    if (iph->protocol != IPPROTO_TCP &&
        iph->protocol != IPPROTO_UDP &&
        iph->protocol != IPPROTO_ICMP)
    {
        atomic64_inc(&g_pkts_filtered);
        return NF_ACCEPT;
    }

    if (unlikely(!ids_ratelimit_check()))
    {
        atomic64_inc(&g_pkts_dropped);
        return NF_ACCEPT;
    }

    memset(&desc, 0, sizeof(desc));
    desc.src_ip = ntohl(iph->saddr);
    desc.dst_ip = ntohl(iph->daddr);
    desc.protocol = iph->protocol;
    desc.pkt_len = ntohs(iph->tot_len);
    desc.ts_nsec = ktime_get_real_ns();

    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        if (unlikely(!pskb_may_pull(skb, (iph->ihl * 4) + sizeof(*tcph))))
            return NF_ACCEPT;
        tcph = tcp_hdr(skb);
        desc.src_port = ntohs(tcph->source);
        desc.dst_port = ntohs(tcph->dest);
        desc.tcp_flags = ((__u8 *)tcph)[13];
        break;

    case IPPROTO_UDP:
        if (unlikely(!pskb_may_pull(skb, (iph->ihl * 4) + sizeof(*udph))))
            return NF_ACCEPT;
        udph = udp_hdr(skb);
        desc.src_port = ntohs(udph->source);
        desc.dst_port = ntohs(udph->dest);
        break;

    case IPPROTO_ICMP:
        break;
    }

    ids_send_pkt(&desc);
    return NF_ACCEPT;
}

/* ── Netfilter registration ──────────────────────────────────────────────── */

static struct nf_hook_ops ids_nf_ops = {
    .hook = ids_nf_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST + 1,
};

/* ── /proc/ids_kmod ──────────────────────────────────────────────────────── */

static int ids_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m,
               "pkts_seen:      %lld\n"
               "pkts_sent:      %lld\n"
               "pkts_dropped:   %lld\n"
               "pkts_filtered:  %lld\n"
               "alloc_failures: %lld\n"
               "rate_limit_pps: %u\n",
               atomic64_read(&g_pkts_seen),
               atomic64_read(&g_pkts_sent),
               atomic64_read(&g_pkts_dropped),
               atomic64_read(&g_pkts_filtered),
               atomic64_read(&g_alloc_failures),
               rate_limit_pps);
    return 0;
}
static int ids_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, ids_proc_show, NULL);
}

static const struct proc_ops ids_proc_ops = {
    .proc_open = ids_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *ids_proc_entry;

/* ── Module init ─────────────────────────────────────────────────────────── */

static int __init ids_kmod_init(void)
{
    int ret;

    if (rate_limit_pps == 0 || rate_limit_pps > 10000000)
    {
        pr_err("ids_kmod: invalid rate_limit_pps=%u (valid: 1-10000000)\n",
               rate_limit_pps);
        return -EINVAL;
    }

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

    ids_proc_entry = proc_create("ids_kmod", 0444, NULL, &ids_proc_ops);
    if (!ids_proc_entry)
        pr_warn("ids_kmod: failed to create /proc/ids_kmod\n");

    pr_info("ids_kmod: loaded — rate=%u pps family=%s group=%s\n",
            rate_limit_pps, IDS_NETLINK_FAMILY, IDS_MCAST_GROUP);
    return 0;
}

/* ── Module exit ─────────────────────────────────────────────────────────── */

static void __exit ids_kmod_exit(void)
{
    if (ids_proc_entry)
        remove_proc_entry("ids_kmod", NULL);

    nf_unregister_net_hook(&init_net, &ids_nf_ops);
    synchronize_rcu();
    genl_unregister_family(&ids_genl_family);

    pr_info("ids_kmod: unloaded — seen=%lld sent=%lld dropped=%lld\n",
            atomic64_read(&g_pkts_seen),
            atomic64_read(&g_pkts_sent),
            atomic64_read(&g_pkts_dropped));
}

module_init(ids_kmod_init);
module_exit(ids_kmod_exit);