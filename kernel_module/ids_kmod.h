#pragma once
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/* Netlink family name and version */
#define IDS_NETLINK_FAMILY "ids_kmod"
#define IDS_NETLINK_VERSION 1

/* Generic Netlink multicast group */
#define IDS_MCAST_GROUP "ids_events"

/* Netlink message attributes */
enum ids_attr
{
    IDS_ATTR_UNSPEC,
    IDS_ATTR_PKT, /* nested: full packet descriptor */
    __IDS_ATTR_MAX,
};
#define IDS_ATTR_MAX (__IDS_ATTR_MAX - 1)

/* Commands */
enum ids_cmd
{
    IDS_CMD_UNSPEC,
    IDS_CMD_PKT_EVENT, /* kernel → userspace: new packet */
    __IDS_CMD_MAX,
};
#define IDS_CMD_MAX (__IDS_CMD_MAX - 1)

/* Flat packet descriptor sent over netlink (fixed-size for easy parsing) */
#pragma pack(push, 1)
struct ids_pkt_desc
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol; /* 6=TCP, 17=UDP, 1=ICMP */
    uint8_t tcp_flags;
    uint16_t pkt_len;
    uint64_t ts_nsec; /* ktime_get_ns() */
};
#pragma pack(pop)