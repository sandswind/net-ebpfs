#ifndef __NET_FAKE_COMMON_H
#define __NET_FAKE_COMMON_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define IPV4_HDR_LEN_NO_OPT 20
#define MAX_SAMPLE_SIZE     2048ul
#define MAX_TCP_CONNECTION  1280000
#define MAX_CPUS            128

#define MIN(a, b)   ((a) < (b) ? (a) : (b))

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

#ifdef TABLE
struct conn_meta {
    __be32 src;
    __be32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
};
#endif

struct target_meta {
    __be32 dst;
    __u16 dport;
};

struct packet_meta {
    __be32 src;
    __be32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u8   l4_proto;
    __u8   flags;
    __u16  eth_off;
    __u16  ip_off;
    __u16  tcp_off;
    __u32  data_len;
    __u32  pkt_len;
    __u32  seq;
};

#ifdef TABLE
struct bpf_map_def SEC("maps") conn_map = {
    .type        = BPF_MAP_TYPE_LPM_TRIE,
    .key_size    = sizeof(struct conn_meta),
    .value_size  = 1,
    .max_entries = MAX_TCP_CONNECTION,
};

#endif

struct bpf_map_def SEC("maps") target_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct target_meta),
    .value_size  = 1,
    .max_entries = MAX_TCP_CONNECTION,
};

struct bpf_map_def SEC("maps") dump_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_CPUS,
};

#endif


