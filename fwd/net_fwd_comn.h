#ifndef __COMMON_H
#define __COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <uapi/linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/ptrace.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#define F_ICMP (1 << 0)
// tcp packet had syn flag set
#define F_SYN_SET (1 << 1)
#define F_PSH_SET (1 << 2)
#define F_FIN_SET (1 << 3)
#define F_RST_SET (1 << 4)

#ifndef MAC_BLACKLIST_MAX_ENTRIES
#define MAC_BLACKLIST_MAX_ENTRIES 4096
#endif

#ifndef V4_BLACKLIST_MAX_ENTRIES
#define V4_BLACKLIST_MAX_ENTRIES 10000
#endif

#ifndef XDP_MAX_ACTIONS
#define XDP_MAX_ACTIONS (XDP_REDIRECT + 1)
#endif

#ifndef DEFAULT_TTL
#define DEFAULT_TTL 64
#endif

/* Fragment Offset */
#define RTE_IPV4_HDR_DF_SHIFT           14
#define RTE_IPV4_HDR_MF_SHIFT           13
#define IPV4_HDR_DF_MASK                (1 << RTE_IPV4_HDR_DF_SHIFT)
#define IPV4_HDR_MF_MASK                (1 << RTE_IPV4_HDR_MF_SHIFT)

#define MIN(a, b)   ((a) < (b) ? (a) : (b))

#define MAX_SAMPLE_SIZE          2048ul
#define IPV4_HDR_LEN_NO_OPT      20
#define MAX_VIPS                 1024
#define MAX_CPUS                 128
#define MAX_SERVERS              512

#define STAT_MAC_BLACKLIST_HIT        0
#define STAT_V4_BLACKLIST_HIT         1
#define STAT_VIP_NOHIT                2
#define STAT_LB_NOHIT                 3

#ifdef DEBUG
#define bpf_print(fmt, ...)                     \
        ({                          \
            char ____fmt[] = fmt;               \
            bpf_trace_printk(____fmt, sizeof(____fmt),  \
                     ##__VA_ARGS__);            \
        })
#else
#define bpf_print(fmt, ...) { } while (0)
#endif


#ifdef VLAN

struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#endif

struct lpm_key {
    __u32 prefixlen;
    __u32 address;
};

struct packet_meta {
    __be32 src;
    __be32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u16  l3_proto;
    __u8   l4_proto;
    __u8   flags;
    __u32  data_len;
    __u32  pkt_len;
    __u32  seq;
};

#ifdef VIP

struct vip_meta {
    __u32 vip;
    __u16 port;
    __u8 proto;
};

#endif

#ifdef TUNNEL
struct iptnl_meta {
    __u32 saddr;
    __u32 daddr;
    __u8 dmac[6];
};
#endif

struct counter {
    __u64 packets;
    __u64 bytes;
};

struct bpf_map_def SEC("maps") mac_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = ETH_ALEN,
    .value_size = 1,
    .max_entries = MAC_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") v4_blacklist = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_key),
    .value_size = 1,
    .max_entries = V4_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

#ifdef VIP
struct bpf_map_def SEC("maps") vip_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct vip_meta),
    .value_size = 1,
    .max_entries = MAX_VIPS,
    .map_flags = BPF_F_NO_PREALLOC,
};
#endif

#ifdef TUNNEL
struct bpf_map_def SEC("maps") servers = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct vip_meta),
    .value_size = sizeof(struct iptnl_meta),
    .max_entries = MAX_SERVERS,
};
#endif

struct bpf_map_def SEC("maps") perf_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_CPUS,
};

struct bpf_map_def SEC("maps") action_counter = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counter),
    .max_entries = XDP_MAX_ACTIONS,
};

struct bpf_map_def SEC("maps") hit_counter = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,
};

__attribute__((__always_inline__))
static inline __u64 calc_offset(__u32 nh_off, bool is_icmp)
{
    __u64 off = nh_off;

    off += sizeof(struct iphdr);
    if (is_icmp) {
        off += (sizeof(struct icmphdr) + sizeof(struct iphdr));
    }
    return off;
}

__attribute__((__always_inline__))
static inline __u64 ether_addr_to_u64(__u8 *addr)
{
    __u64 u = 0;
    int i;

    for (i = ETH_ALEN; i >= 0; i--)
        u = u << 8 | addr[i];
    return u;
}

__attribute__((__always_inline__))
static inline int parse_udp(void *data, void *data_end, __u32 nh_off, __u64 *offset, struct packet_meta *pckt)
{
    bool is_icmp = !((pckt->flags & F_ICMP) == 0);
    __u64 off = calc_offset(nh_off, is_icmp);
    struct udphdr *udp = NULL;

    udp = data + off;

    if (udp + 1 > data_end) {
        return XDP_DROP;
    }

    pckt->port16[0] = bpf_ntohs(udp->source);
    pckt->port16[1] = bpf_ntohs(udp->dest);
    *offset = off;

    return -1;
}

__attribute__((__always_inline__))
static inline int parse_tcp(void *data, void *data_end, __u32 nh_off, __u64 *offset, struct packet_meta *pckt)
{
    bool is_icmp = !((pckt->flags & F_ICMP) == 0);
    __u64 off = calc_offset(nh_off, is_icmp);
    struct tcphdr *tcp = NULL;
    tcp = data + off;

    if (tcp + 1 > data_end) {
        return XDP_DROP;
    }

    if (tcp->syn) {
        bpf_print("tcp syn\n");
        pckt->flags |= F_SYN_SET;
    }

    if (tcp->psh) {
        bpf_print("tcp psh\n");
        pckt->flags |= F_PSH_SET;
    }

    if (tcp->fin) {
        bpf_print("tcp fin\n");
        pckt->flags |= F_FIN_SET;
    }

    if (tcp->rst) {
        bpf_print("tcp rst\n");
        pckt->flags |= F_RST_SET;
    }

    pckt->port16[0] = bpf_ntohs(tcp->source);
    pckt->port16[1] = bpf_ntohs(tcp->dest);
    pckt->seq   = tcp->seq;
    *offset = off;

    return -1;
}

__attribute__((__always_inline__))
static inline int parse_icmp(void *data, void *data_end, __u64 off,  struct packet_meta *pckt)
{
    struct icmphdr *icmp_hdr = NULL;
    struct iphdr *iph = NULL;
    icmp_hdr = data + off;

    if (icmp_hdr + 1 > data_end) {
        return XDP_DROP;
    }

    bpf_print("icmp type:%d, code:%d\n", icmp_hdr->type, icmp_hdr->code);

//    if (icmp_hdr->type == ICMP_ECHO) {
//        bpf_print("icmp echo\n");
//    } else if (icmp_hdr->type != ICMP_DEST_UNREACH) {
//        bpf_print("icmp unreach \n");
//        return  XDP_DROP;
//    }

    return XDP_PASS;
}

__attribute__((__always_inline__))
static inline __u32 update_action_stats(__u64 bytes, __u32 action)
{
    struct counter *counter = bpf_map_lookup_elem(&action_counter, &action);
    if (!counter) {
        struct counter c = {
            .packets = 1,
            .bytes = bytes,
        };

        bpf_map_update_elem(&action_counter, &action, &c, BPF_NOEXIST);
    } else {
        counter->packets += 1;
        counter->bytes += bytes;
    }

    return action;
}

//__attribute__((__always_inline__))
//static inline __u16 csum_fold_helper(__u64 csum)
//{
//    int i;
//#pragma unroll
//    for (i = 0; i < 4; i ++) {
//        if (csum >> 16)
//            csum = (csum & 0xffff) + (csum >> 16);
//    }
//    return ~csum;
//}
//
//__attribute__((__always_inline__))
//static inline void ipv4_csum(void *data_start, int data_size,  __u64 *csum)
//{
//    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
//    *csum = csum_fold_helper(*csum);
//}
//
//__attribute__((__always_inline__))
//static inline void ipv4_csum_inline(void *iph, __u64 *csum)
//{
//    __u16 *next_iph_u16 = (__u16 *)iph;
//    #pragma clang loop unroll(full)
//    for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
//        *csum += *next_iph_u16++;
//    }
//    *csum = csum_fold_helper(*csum);
//}
//
//__attribute__((__always_inline__))
//static inline void create_v4_hdr(struct iphdr *iph, __u8 tos, __u32 saddr, __u32 daddr, __u16 pkt_bytes,  __u8 proto)
//{
//    __u64 csum = 0;
//    iph->version = 4;
//    iph->ihl = 5;
//    iph->frag_off = 0;
//    iph->protocol = proto;
//    iph->check = 0;
//#ifdef COPY_TOS
//    iph->tos = tos;
//#else
//    iph->tos = DEFAULT_TOS;
//#endif
//    iph->tot_len = bpf_htons(pkt_bytes + sizeof(struct iphdr));
//    iph->daddr = daddr;
//    iph->saddr = saddr;
//    iph->ttl = DEFAULT_TTL;
//    ipv4_csum_inline(iph, &csum);
//    iph->check = csum;
//}
//
//__attribute__((__always_inline__))
//static inline bool encap_v4(struct xdp_md *xdp, struct ctl_value *cval, struct packet_meta *pckt, struct real_definition *dst, __u32 pkt_bytes)
//{
//    void* data;
//    void* data_end;
//    struct iphdr* iph;
//    struct eth_hdr* new_eth;
//    struct eth_hdr* old_eth;
//
//    __u32 ip_suffix = bpf_htons(pckt->port16[0]);
//    ip_suffix <<= 16;
//    ip_suffix ^= pckt->src;
//    __u64 csum = 0;
//
//    // ipip encap
//    if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct iphdr))) {
//        return false;
//    }
//
//    data = (void*)(long)xdp->data;
//    data_end = (void*)(long)xdp->data_end;
//    new_eth = data;
//    iph = data + sizeof(struct eth_hdr);
//    old_eth = data + sizeof(struct iphdr);
//    if (new_eth + 1 > data_end || old_eth + 1 > data_end || iph + 1 > data_end) {
//        return false;
//    }
//    __builtin_memcpy(new_eth->eth_dest, cval->mac, 6);
//    __builtin_memcpy(new_eth->eth_source, old_eth->eth_dest, 6);
//    new_eth->eth_proto = BE_ETH_P_IP;
//
//    create_v4_hdr(iph, pckt->tos, ((0xFFFF0000 & ip_suffix) | IPIP_V4_PREFIX), dst->dst, pkt_bytes, IPPROTO_IPIP);
//
//    return true;
//}

#endif
