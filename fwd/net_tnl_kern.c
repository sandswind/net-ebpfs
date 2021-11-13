#include <stddef.h>
#include <stdbool.h>
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#ifndef MAC_MAX_ENTRIES
#define MAC_MAX_ENTRIES 4096
#endif

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

struct bpf_map_def SEC("maps") mac_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = ETH_ALEN,
    .value_size = 1,
    .max_entries = MAC_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

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
static inline bool decap_ipv4(struct xdp_md *xdp, void **data, void **data_end)
{
    struct ethhdr *new_eth = NULL;
    struct ethhdr *old_eth = NULL;
    struct iphdr  *iph = NULL;

    old_eth = *data;
    new_eth = *data + sizeof(struct iphdr);

    iph = (void *)(long)xdp->data + sizeof(*new_eth);
    if (iph->ttl == 8) {
        bpf_print("ttl hit, ttl is 8\n");
    }

    __builtin_memcpy(new_eth->h_source, old_eth->h_source, 6);
    __builtin_memcpy(new_eth->h_dest, old_eth->h_dest, 6);

    new_eth->h_proto = ETH_P_IP;

    if (bpf_xdp_adjust_head(xdp, (int)sizeof(struct iphdr))) {
        return false;
    }

    *data = (void*)(long)xdp->data;
    *data_end = (void*)(long)xdp->data_end;

    return true;
}


SEC("netfwd")
int net_tunnel(struct xdp_md *ctx)
{
    __u32 nh_off = 0;
    __u32 eth_proto = 0;
    __u32 action = XDP_PASS;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    nh_off = sizeof(struct ethhdr);

    if (data + nh_off > data_end) {
        action = XDP_DROP;
        goto ret;
    }
    eth_proto = bpf_ntohs(eth->h_proto);

    if (eth_proto == ETH_P_IP) {
        if (bpf_map_lookup_elem(&mac_blacklist, eth->h_source)) {
            bpf_print("mac hit, decap source:%llu\n",  ether_addr_to_u64(eth->h_source));
            if (!decap_ipv4(ctx, &data, &data_end)) {
                action = XDP_DROP;
                bpf_print("mac hit, decap errror, source:%llu\n",  ether_addr_to_u64(eth->h_source));
            } else {
                bpf_print("mac hit, decap okay, source:%llu\n",  ether_addr_to_u64(eth->h_source));
            }
        }
    }

ret:
    return int(action);
}

char _license[] SEC("license") = "GPL";
