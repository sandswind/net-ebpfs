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
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/ptrace.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#define F_ICMP (1 << 0)
#define F_SYN_SET (1 << 1)

#ifndef V4_BLACKLIST_MAX_ENTRIES
#define V4_BLACKLIST_MAX_ENTRIES 10000
#endif

#ifndef XDP_MAX_ACTIONS
#define XDP_MAX_ACTIONS (XDP_REDIRECT + 1)
#endif

#define IPV4_HDR_LEN_NO_OPT      20
#define IP_FRAGMENTED            0xFF3F
#define MAX_TCP_PORT             0xFFFF /* power of 2 */
#define MAX_CPUS                 128
#define MAX_CLIENTS              1500000
#define MAX_FLOWS                (MAX_CLIENTS * 2)
#define MAX_LISTEN_PORTS         2048

#define STAT_V4_BLACKLIST_HIT         1
#define STAT_VIP_NOHIT                2

#define bpf_print(fmt, ...)                                    \
({                                                              \
               char ____fmt[] = fmt;                            \
               bpf_trace_printk(____fmt, sizeof(____fmt),       \
                                ##__VA_ARGS__);                 \
})

enum {
    TRACE_TO_LXC,
    TRACE_TO_PROXY,
    TRACE_TO_HOST,
    TRACE_TO_STACK,
    TRACE_TO_OVERLAY,
    TRACE_FROM_LXC,
    TRACE_FROM_PROXY,
    TRACE_FROM_HOST,
    TRACE_FROM_STACK,
    TRACE_FROM_OVERLAY,
    TRACE_FROM_NETWORK,
};

#ifdef VLAN

struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#endif

struct lpm_key {
    __u32 prefixlen;
    __u8 address[4];
};

struct pkt_dst {
    __u32 daddr;
    __u16 dport;
} __attribute__((__packed__));

struct rule_value {
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
    __u8 dmac[6];
    bool aggressive_reap;
};

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct egress_nat_value {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 dmac[6];
    bool aggressive_reap;
    __u64 pkt_cnt;
    __u64 byte_cnt;
};

/* Perf Event Map */
struct perf_value {
    struct flow_key client;
    struct egress_nat_value client_nat;
    __u16 action;
} __attribute__((__packed__));

struct bpf_map_def SEC("maps") v4_blacklist = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_key),
    .value_size = 1,
    .max_entries = V4_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

/* Next Hop Map */
struct bpf_map_def SEC("maps") server_rules = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct pkt_dst),
    .value_size = sizeof(struct rule_value),
    .max_entries = MAX_LISTEN_PORTS,
};

/* Active Flows Map */
struct bpf_map_def SEC("maps") nat_flows_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct egress_nat_value),
    .max_entries = MAX_FLOWS,
};

/* Stats Map */
struct bpf_map_def SEC("maps") prog_stats = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 2,
};

/* Perf Events - New Conns Notifier */
struct bpf_map_def SEC("maps") perf_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_CPU,
};

__attribute__((__always_inline__))
static inline __u64 calc_offset(bool is_icmp)
{
    __u64 off = sizeof(struct ethhdr);

    off += sizeof(struct iphdr);
    if (is_icmp) {
        off += (sizeof(struct icmphdr) + sizeof(struct iphdr));
    }
    return off;
}

__attribute__((__always_inline__))
static inline int parse_udp(void *data, void *data_end, __u64 *offset, struct packet_meta *pckt)
{

    bool is_icmp = !((pckt->flags & F_ICMP) == 0);
    __u64 off = calc_offset(is_icmp);
    struct udphdr *udp = NULL;

    udp = data + off;

    if (udp + 1 > data_end) {
        return XDP_DROP;
    }

    pckt->sport = udp->source;
    pckt->dport = udp->dest;
    *offset = off;

    return -1;
}

__attribute__((__always_inline__))
static inline int parse_tcp(void *data, void *data_end, __u64 *offset, struct packet_meta *pckt)
{

    bool is_icmp = !((pckt->flags & F_ICMP) == 0);
    __u64 off = calc_offset(is_icmp);
    struct tcphdr *tcp = NULL;
    tcp = data + off;

    if (tcp + 1 > data_end) {
        return XDP_DROP;
    }

    if (tcp->syn) {
        pckt->flags |= F_SYN_SET;
    }

    pckt->sport = tcp->source;
    pckt->dport = tcp->dest;
    pckt->seq   = tcp->seq;
    *offset = off;

    return -1;
}

__attribute__((__always_inline__))
static inline void notify_host(struct xdp_md *ctx, struct flow_key *ingress, struct egress_nat_value *egress, __u16 action)
{
    struct perf_value perf_log = {0};

    memcpy(&perf_log.client, ingress, sizeof(struct flow_key));
    memcpy(&perf_log.client_nat, egress, sizeof(struct egress_nat_value));
    perf_log.action = action;
    bpf_perf_event_output(ctx, &perf_map, 0 | BPF_F_CURRENT_CPU, &perf_log, sizeof(perf_log));
}

__attribute__((__always_inline__))
static inline int get_unique_nat_port(__u32 nat_saddr, __u32 nat_daddr, __u16 nat_dport)
{
    struct egress_nat_value *value;
    struct flow_key nat_id = {};

    nat_id.daddr = nat_saddr;
    nat_id.saddr = nat_daddr;
    nat_id.sport = nat_dport;

    #pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++) { /* 16 attempts to find a unique tuple */
        nat_id.dport = bpf_get_prandom_u32() & MAX_TCP_PORT;
        if (nat_id.dport == 0) /* disallow port 0 */
            nat_id.dport++;

        value = bpf_map_lookup_elem(&nat_flows_map, &nat_id);
        if (!value) /* tuple available within map */
            return nat_id.dport;
    }
    return 0;
}
__attribute__((__always_inline__))
static inline void update_header_field(__u16 *csum, __u16 *old_val, __u16 *new_val)
{
    __u32 new_csum_value;
    __u32 new_csum_comp;
    __u32 undo;

    undo = ~((__u32) *csum) + ~((__u32) *old_val);
    new_csum_value = undo + (undo < ~((__u32) *old_val)) + (__u32) *new_val;
    new_csum_comp = new_csum_value + (new_csum_value < ((__u32) *new_val));
    new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
    new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
    *csum = (__u16) ~new_csum_comp;
    *old_val = *new_val;
}

__attribute__((__always_inline__))
static inline void swap_mac(void *data, struct ethhdr *orig_eth)
{
    struct ethhdr *eth;
    eth = data;
    __builtin_memcpy(eth->h_source, orig_eth->h_dest , ETH_ALEN);
    __builtin_memcpy(eth->h_dest, orig_eth->h_source, ETH_ALEN);
    eth->h_proto = orig_eth->h_proto;
}

__attribute__((__always_inline__))
static int min_helper(int a, int b)\
{
    return a < b ? a : b;
}

__attribute__((__always_inline__))
static inline void submit_event(struct xdp_md *ctx, void *map, __u32 event_id, void *data, __u32 size)
{
    struct event_metadata md = {0};
    __u64 flags = BPF_F_CURRENT_CPU;

    md.event = event_id;
    md.pkt_size = size;
    md.data_len = min_helper(size, MAX_EVENT_SIZE);

    flags |= (__u64) md.data_len << 32;
    bpf_perf_event_output(ctx, map, flags, &md, sizeof(struct event_metadata));
}


#endif
