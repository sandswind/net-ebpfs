#include "net_fwd_comn.h"

#ifdef TUNNEL
__attribute__((__always_inline__))
static inline void set_ethhdr(struct ethhdr *new_eth, const struct ethhdr *old_eth,
        const struct iptnl_meta *tnl, __be16 h_proto)
{
    __builtin_memcpy(new_eth->h_source, old_eth->h_dest, sizeof(new_eth->h_source));
    __builtin_memcpy(new_eth->h_dest, tnl->dmac, sizeof(new_eth->h_dest));
    new_eth->h_proto = h_proto;
}
#endif

__attribute__((__always_inline__))
static inline int process_header(struct packet_meta *pckt, __u8 *protocol, __u64 off,
                                     __u16 *pkt_bytes, void *data, void *data_end)
{
    struct iphdr *iph = NULL;

    iph = data + off;
    if (iph + 1 > data_end) {
        return XDP_DROP;
    }

    if (iph->ihl != 5) {
        bpf_print("ihl is not 5\n");
        return XDP_DROP;
    }

    *protocol = iph->protocol;
    pckt->l3_proto = *protocol;
    *pkt_bytes = bpf_ntohs(iph->tot_len);
    off += IPV4_HDR_LEN_NO_OPT;

//    ntohs(iph->frag_off)
//    if((frag_off & 0x1FFF) != 0)
//    if ((iph->frag_off & IPV4_HDR_DF_MASK) != 0) {
        if (*protocol == IPPROTO_ICMP) {
            bpf_print("icmp pkg\n");
            return parse_icmp(data, data_end, off, pckt);
        } else {
            pckt->src = iph->saddr;
            pckt->dst = iph->daddr;
        }
        return -1;
//    }

    bpf_print("PCKT_FRAGMENTED\n");
    return XDP_DROP;
}

SEC("netfwd")
int net_fwd(struct xdp_md *ctx)
{
    __u8 protocol;
    __u16 pkt_bytes;
    __u16 *next_iph_u16 = NULL;
    __u32 eth_proto = 0;
    __u32 nh_off = 0;
    __u64 ip_off = 0;
    __u32 action = XDP_PASS;
    __u64 *stats_cntr;
    __u64 len = 0;
    __u32 stats_key = 0;
    __u32 sample_size = 0;
    __u32 csum = 0;
    int i = 0;
    int  result = 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct packet_meta pckt = {0};
    struct lpm_key  key = {0};
#ifdef VIP
    struct vip_meta    vip = {0};
#endif

#ifdef TUNNEL
    struct iptnl_meta *tnl =  NULL;
    struct ethhdr     *new_eth = NULL;
    struct iphdr      *iph = NULL;
#endif

    nh_off = sizeof(struct ethhdr);

    if (data + nh_off > data_end) {
        action = XDP_DROP;
        goto ret;
    }
    len = data_end - data;
    pckt.pkt_len = len;

    if (bpf_map_lookup_elem(&mac_blacklist, eth->h_source)) {
        action = XDP_DROP;
        stats_key = STAT_MAC_BLACKLIST_HIT;
        stats_cntr = bpf_map_lookup_elem(&hit_counter, &stats_key);
        if (stats_cntr) {
            stats_cntr += 1;;
        }
        bpf_print("mac blacklist hit, source:%llu\n",  ether_addr_to_u64(eth->h_source));
        goto ret;
    }

    eth_proto = bpf_ntohs(eth->h_proto);

#ifdef VLAN

#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
            struct vlan_hdr *vlan = data + nh_off;
            if (vlan + 1 > data_end) {
                return XDP_DROP;
            }
            nh_off += sizeof(*vlan);
            eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        }
    }

#endif

    bpf_print("parse l2>> source:%llu dest:%llu eth_proto:%d\n",
            ether_addr_to_u64(eth->h_source), ether_addr_to_u64(eth->h_dest), eth_proto);

    pckt.l3_proto = eth_proto;
    if (eth_proto == ETH_P_IP) {
        result = process_header(&pckt, &pckt.l4_proto, nh_off, &pkt_bytes, data, data_end);
        if (result > 0) {
            goto ret;
        }
    } else {
        goto ret;
    }

    key.address = pckt.src;
    key.prefixlen = 32;

    if (bpf_map_lookup_elem(&v4_blacklist, &key)) {
        action = XDP_DROP;
        stats_key = STAT_V4_BLACKLIST_HIT;
        stats_cntr = bpf_map_lookup_elem(&hit_counter, &stats_key);
        if (stats_cntr) {
            stats_cntr += 1;
        }
        bpf_print("v4 blacklist hit, src:%u, dst:%u\n", pckt.src, pckt.dst);
        goto ret;
    }

    bpf_print("v4 blacklist ok, src:%u, dst:%u [proto:%u]\n", pckt.src, pckt.dst, pckt.l4_proto);

    if (pckt.l4_proto == IPPROTO_TCP) {
        result = parse_tcp(data, data_end, nh_off, &ip_off, &pckt);
        if (result > 0) {
            action = result;
            goto ret;
        }
    } else if (pckt.l4_proto == IPPROTO_UDP) {
        result = parse_udp(data, data_end, nh_off, &ip_off, &pckt);
        if (result > 0) {
            action = result;
            goto ret;
        }
    } else {
        goto ret;
    }


#ifdef VIP
    vip.vip = pckt.dst;
    vip.port = pckt.port16[1];
    vip.proto = pckt.l4_proto;

    if (!bpf_map_lookup_elem(&vip_map, &vip)) {
        vip.port = 0;
        if (!bpf_map_lookup_elem(&vip_map, &vip)) {
            action = XDP_DROP;
            stats_key = STAT_VIP_NOHIT;
            stats_cntr = bpf_map_lookup_elem(&hit_counter, &stats_key);
            if (stats_cntr) {
                stats_cntr += 1;
            }
            bpf_print("vip is not hit, vip:%u, port:%u\n", vip.vip, pckt.port16[1]);
            goto ret;
        }
    }
#endif

#ifdef TUNNEL
    tnl = bpf_map_lookup_elem(&servers, &vip);
    if (!tnl) {
        bpf_print("no server for key, vip:%u, port:%u\n", vip.vip, vip.port);
        goto ret;
    }

    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr))) {
        bpf_print("bpf_xdp_adjust_head, drop it\n");
        action = XDP_DROP;
        goto ret;
    }

    new_eth = data;
    iph = data + sizeof(*new_eth);
    eth = data + sizeof(*iph);

    if (new_eth + 1 > data_end || eth + 1 > data_end || iph + 1 > data_end) {
        bpf_print("eth check failture, drop it\n");
        action = XDP_DROP;
        goto ret;
    }

    set_ethhdr(new_eth, eth, tnl, bpf_htons(ETH_P_IP));

    iph->version = 4;
    iph->ihl = sizeof(*iph) >> 2;
    iph->frag_off = 0;
    iph->protocol = IPPROTO_IPIP;
    iph->check = 0;
    iph->tos = 0;
    iph->tot_len = bpf_htons(pkt_bytes + sizeof(*iph));
    iph->daddr = tnl->daddr;
    iph->saddr = tnl->saddr;
    iph->ttl = 8;

    next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
    for (i = 0; i < sizeof(*iph) >> 1; i++)
        csum += *next_iph_u16++;

    iph->check = ~((csum & 0xffff) + (csum >> 16));
    action = XDP_TX;
#endif

    bpf_print("pass all>> source:%llu dest:%llu dst:%u\n",
            ether_addr_to_u64(eth->h_source), ether_addr_to_u64(eth->h_dest), pckt.port16[1]);

    pckt.data_len = len - ip_off;
    sample_size = MIN(pckt.pkt_len, MAX_SAMPLE_SIZE);

    bpf_perf_event_output(ctx, &perf_map,(__u64)sample_size << 32 | BPF_F_CURRENT_CPU, &pckt, sizeof(struct packet_meta));

ret:
    return update_action_stats(pckt.pkt_len, action);
}

char _license[] SEC("license") = "GPL";
