/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ids_kmod.h — Shared kernel/userspace interface for IDS kernel module.
 *
 * This header is included by both the kernel module (ids_kmod.c) and
 * the userspace receiver (src/capture/NetlinkReceiver.cpp).
 *
 * Rules:
 *   - No kernel-only types in the shared struct (no __be32 etc.)
 *   - Fixed-size fields only — no pointers
 *   - Explicit padding to guarantee identical layout on both sides
 *   - Use __attribute__((packed)) NOT #pragma pack (more portable)
 */

#ifndef IDS_KMOD_H
#define IDS_KMOD_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u8 ids_u8;
typedef __u16 ids_u16;
typedef __u32 ids_u32;
typedef __u64 ids_u64;
#else
#include <stdint.h>
typedef uint8_t ids_u8;
typedef uint16_t ids_u16;
typedef uint32_t ids_u32;
typedef uint64_t ids_u64;
#endif

/* ── Generic Netlink constants ──────────────────────────────────────────── */

#define IDS_NETLINK_FAMILY "ids_kmod"
#define IDS_NETLINK_VERSION 1
#define IDS_MCAST_GROUP "ids_events"

/* ── Netlink attributes ─────────────────────────────────────────────────── */

enum ids_attr
{
    IDS_ATTR_UNSPEC = 0,
    IDS_ATTR_PKT,   /* NLA_BINARY: struct ids_pkt_desc */
    IDS_ATTR_STATS, /* NLA_BINARY: struct ids_kmod_stats */
    __IDS_ATTR_MAX,
};
#define IDS_ATTR_MAX (__IDS_ATTR_MAX - 1)

/* ── Netlink commands ───────────────────────────────────────────────────── */

enum ids_cmd
{
    IDS_CMD_UNSPEC = 0,
    IDS_CMD_PKT_EVENT,   /* kernel → userspace: packet intercepted */
    IDS_CMD_GET_STATS,   /* userspace → kernel: request stats */
    IDS_CMD_STATS_REPLY, /* kernel → userspace: stats response */
    IDS_CMD_SET_FILTER,  /* userspace → kernel: update BPF filter */
    __IDS_CMD_MAX,
};
#define IDS_CMD_MAX (__IDS_CMD_MAX - 1)

/* ── Protocol identifiers (mirroring IANA) ──────────────────────────────── */

#define IDS_PROTO_ICMP 1
#define IDS_PROTO_TCP 6
#define IDS_PROTO_UDP 17

/* ── TCP flag bits ──────────────────────────────────────────────────────── */

#define IDS_TCP_FIN (1 << 0)
#define IDS_TCP_SYN (1 << 1)
#define IDS_TCP_RST (1 << 2)
#define IDS_TCP_PSH (1 << 3)
#define IDS_TCP_ACK (1 << 4)
#define IDS_TCP_URG (1 << 5)
#define IDS_TCP_ECE (1 << 6)
#define IDS_TCP_CWR (1 << 7)

/* ── Packet descriptor ──────────────────────────────────────────────────── */
/*
 * Sent from kernel to userspace for every intercepted packet.
 * Layout is explicit — no compiler-inserted padding.
 * All multi-byte integers are in HOST byte order (converted in the hook).
 * Total size: 4+4+2+2+1+1+2+8 = 24 bytes.
 */
struct ids_pkt_desc
{
    ids_u32 src_ip;   /* source IPv4 address, host byte order      */
    ids_u32 dst_ip;   /* destination IPv4 address, host byte order  */
    ids_u16 src_port; /* source port, host byte order (0 for ICMP)  */
    ids_u16 dst_port; /* dest port, host byte order (0 for ICMP)    */
    ids_u8 protocol;  /* IDS_PROTO_TCP / UDP / ICMP                 */
    ids_u8 tcp_flags; /* IDS_TCP_* bitmask (0 for non-TCP)          */
    ids_u16 pkt_len;  /* IP total length, host byte order           */
    ids_u64 ts_nsec;  /* ktime_get_real_ns() — wall-clock nanosecs  */
} __attribute__((packed));

/* Compile-time size check — will fail if layout drifts */
#ifdef __KERNEL__
static_assert(sizeof(struct ids_pkt_desc) == 24,
              "ids_pkt_desc size mismatch — check padding");
#endif

/* ── Per-module statistics (returned by IDS_CMD_GET_STATS) ─────────────── */

struct ids_kmod_stats
{
    ids_u64 pkts_seen;        /* total packets seen by the hook         */
    ids_u64 pkts_sent;        /* packets successfully sent to userspace  */
    ids_u64 pkts_dropped;     /* dropped due to alloc failure / ratelim  */
    ids_u64 pkts_filtered;    /* dropped by protocol filter             */
    ids_u64 alloc_failures;   /* genlmsg_new() returned NULL            */
    ids_u32 active_listeners; /* current # of userspace subscribers     */
    ids_u32 _pad;             /* explicit padding to 8-byte boundary    */
} __attribute__((packed));

#endif /* IDS_KMOD_H */