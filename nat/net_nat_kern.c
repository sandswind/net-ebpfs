#include "net_nat_comn.h"

__attribute__((__always_inline__))
static inline int process_nat_udp(void *data, void *data_end, __u64 offset, struct packet_meta *pckt)
{
    struct egress_nat_value return_egress_nat = {};
    struct egress_nat_value new_egress_nat = {};
    struct egress_nat_value *egress_nat;
    struct flow_key return_ingress_flow = {};
    struct flow_key ingress_flow = {};
    struct pkt_dst rule_key = {};
    struct rule_value *rule_val;
    struct udphdr *udp;
    struct iphdr *iph;
    __u16 nat_port = 0;
    __u64 *stats_cntr;
    __u16 *p_iph_16;
    __u32 stats_key;
    bool reap_flow;
    __u32 csum = 0;
    __u16 err = 0;

    iph = data + off;
    if ((void *) (iph + 1) > data_end)
        return XDP_PASS;
    if (iph->ihl != 5)
        return XDP_PASS;

    off += sizeof(struct iphdr);

    /* do not support fragmented packets as L4 headers may be missing */
    if (iph->frag_off & IP_FRAGMENTED)
        return XDP_PASS;

    /* Only process UDP */
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    udp = data + off;
    if ((void *) (udp + 1) > data_end)
        return XDP_PASS;

    /* [Client] -> ingress_flow -> [BPF] -> egress_nat -> [Server] */
    ingress_flow.saddr = iph->saddr;
    ingress_flow.daddr = iph->daddr;
    ingress_flow.sport = udp->source;
    ingress_flow.dport = udp->dest;

    /* Lookup flow map to see if NAT exists */
    egress_nat = bpf_map_lookup_elem(&nat_flows_map, &ingress_flow);
    if (!egress_nat) {
        /* Generate a new NAT flow, get nat dest from map */
        rule_key.daddr = ingress_flow.daddr;
        rule_key.dport = ingress_flow.dport;
        rule_val = bpf_map_lookup_elem(&server_rules, &rule_key);
        if (!rule_val)
            return XDP_PASS; /* if rule does not exist, pass */

        new_egress_nat.saddr = rule_val->saddr;
        new_egress_nat.daddr = rule_val->daddr;
        new_egress_nat.dport = rule_val->dport;

        /* Generate unique nat port, Map NAT is stored in return dir */
        nat_port = get_unique_nat_port(rule_val->saddr, rule_val->daddr,
                           rule_val->dport);
        if (nat_port == 0)
            return XDP_ABORTED; /* no unique port available */
        new_egress_nat.sport = nat_port;

        new_egress_nat.pkt_cnt = 0;
        new_egress_nat.byte_cnt = 0;
        new_egress_nat.aggressive_reap = 0;
        memcpy(new_egress_nat.dmac, rule_val->dmac,
               sizeof(rule_val->dmac));

        /* If this is a reap udp ping flow the forward flow will not be
         * installed into the map, as there should be no further packets
         * from the Client.
         */
        reap_flow = rule_val->aggressive_reap;
        if (!reap_flow) {
            err = bpf_map_update_elem(&nat_flows_map, &ingress_flow,
                          &new_egress_nat, BPF_NOEXIST);
            if (err)
                return XDP_ABORTED;

            notify_host(ctx, &ingress_flow, &new_egress_nat,
                    FLOW_ADD);
        } else if (LOG_REAP_FLOWS) {
            notify_host(ctx, &ingress_flow, &new_egress_nat,
                    FLOW_ADD_REAP);
        }

        /* Add return direction to tuple map for use by future packets
         * [Client] <- return_egress_nat <- [BPF] <- return_ingress_flow <- [Server]
         */
        return_ingress_flow.saddr = new_egress_nat.daddr;
        return_ingress_flow.daddr = new_egress_nat.saddr;
        return_ingress_flow.sport = new_egress_nat.dport;
        return_ingress_flow.dport = nat_port;

        return_egress_nat.saddr = ingress_flow.daddr;
        return_egress_nat.daddr = ingress_flow.saddr;
        return_egress_nat.sport = ingress_flow.dport;
        return_egress_nat.dport = ingress_flow.sport;
        return_egress_nat.pkt_cnt = 0;
        return_egress_nat.byte_cnt = 0;
        return_egress_nat.aggressive_reap = reap_flow;
        memcpy(return_egress_nat.dmac, eth->h_source,
               sizeof(eth->h_source));

        err = bpf_map_update_elem(&nat_flows_map, &return_ingress_flow,
                      &return_egress_nat, BPF_NOEXIST);
        if (err) {
            /* If collision, clean up previous entry and abort */
            bpf_map_delete_elem(&nat_flows_map,
                        &ingress_flow);
            return XDP_ABORTED;
        }

        if (!reap_flow)
            stats_key = STATS_FLOW;
        else
            stats_key = STATS_REAP_ACTIVE;

        stats_cntr = bpf_map_lookup_elem(&prog_stats, &stats_key);
        if (stats_cntr)
            __sync_fetch_and_add(stats_cntr, 1);

        /* Update packet with egress NAT values from stack */
        memcpy(eth->h_source, eth->h_dest, sizeof(eth->h_dest));
        memcpy(eth->h_dest, new_egress_nat.dmac,
               sizeof(new_egress_nat.dmac));

        update_header_field(&udp->check, &udp->dest,
                    &new_egress_nat.dport);
        update_header_field(&udp->check, &udp->source,
                    &new_egress_nat.sport);

        update_header_field(&udp->check, (__u16 *) &iph->saddr,
                    (__u16 *) &new_egress_nat.saddr);
        update_header_field(&udp->check, (__u16 *) &iph->saddr + 1,
                    (__u16 *) &new_egress_nat.saddr + 1);
        update_header_field(&udp->check, (__u16 *) &iph->daddr,
                    (__u16 *) &new_egress_nat.daddr);
        update_header_field(&udp->check, (__u16 *) &iph->daddr + 1,
                    (__u16 *) &new_egress_nat.daddr + 1);

    } else {
        /* Update packet with egress NAT values from map
         * Note: Code duplication is required for calculated NAT values
         * vs pre-existing map values to allow for the NFP JIT
         * to know which hw memory location the NAT data will be
         * obtained from
         */
        memcpy(eth->h_source, eth->h_dest, sizeof(eth->h_dest));
        memcpy(eth->h_dest, egress_nat->dmac, sizeof(egress_nat->dmac));

        update_header_field(&udp->check, &udp->dest,
                    &egress_nat->dport);
        update_header_field(&udp->check, &udp->source,
                    &egress_nat->sport);

        update_header_field(&udp->check, (__u16 *) &iph->saddr,
                    (__u16 *) &egress_nat->saddr);
        update_header_field(&udp->check, (__u16 *) &iph->saddr + 1,
                    (__u16 *) &egress_nat->saddr + 1);
        update_header_field(&udp->check, (__u16 *) &iph->daddr,
                    (__u16 *) &egress_nat->daddr);
        update_header_field(&udp->check, (__u16 *) &iph->daddr + 1,
                    (__u16 *) &egress_nat->daddr + 1);

        if (egress_nat->aggressive_reap) {
            /* if it's the response pkt for the reap, cleanup map */
            err = bpf_map_delete_elem(&nat_flows_map,
                          &ingress_flow);
            if (err == 0) {
                stats_key = STATS_REAP_ACTIVE;
                stats_cntr = bpf_map_lookup_elem(&prog_stats,
                                 &stats_key);
                if (stats_cntr)
                    __sync_fetch_and_add(stats_cntr, -1);
                if (LOG_REAP_FLOWS)
                    notify_host(ctx, &ingress_flow,
                            egress_nat, FLOW_DELETE);
            }
        } else {
            /* increment tuple flow counters */
            __sync_fetch_and_add(&egress_nat->pkt_cnt, 1);
            __sync_fetch_and_add(&egress_nat->byte_cnt,
                         data_end - data);
        }
    }

    /* Update IPv4 header checksum */
    iph->check = 0;
    p_iph_16 = (__u16 *)iph;
    #pragma clang loop unroll(full)
    for (int i = 0; i < (int)sizeof(*iph) >> 1; i++)
        csum += *p_iph_16++;
    iph->check = ~((csum & 0xffff) + (csum >> 16));

    return XDP_TX;
}

__attribute__((__always_inline__))
static inline int process_header(struct packet_meta *pckt, __u16 *protocol, __u64 off,
                                     __u16 *pkt_bytes, void *data, void *data_end)
{
    struct iphdr *iph = NULL;

    iph = data + off;
    if (iph + 1 > data_end) {
        return XDP_DROP;
    }

    if (iph->ihl != 5) {
        // if len of ipv4 hdr is not equal to 20bytes that means that header
        // contains ip options, and we dont support em
        return XDP_DROP;
    }

    pckt->tos = iph->tos;
    *protocol = iph->protocol;
    pckt->l3_proto = *protocol;
    *pkt_bytes = bpf_ntohs(iph->tot_len);
    off += IPV4_HDR_LEN_NO_OPT;

    if (iph->frag_off & PCKT_FRAGMENTED) {
        // we drop fragmented packets.
        return XDP_DROP;
    }

    if (*protocol == IPPROTO_ICMP) {
        // pass icmp
        return XDP_PASS;
    } else {
        pckt->src = iph->saddr;
        pckt->dst = iph->daddr;
    }
    return -1;
}

SEC("net_nat")
int net_nat(struct xdp_md *ctx)
{
    __u8 protocol;
    __u16 pkt_bytes;
    __u32 eth_proto = 0;
    __u32 nh_off = 0;
    __u64 ip_off = 0;
    __u32 action = XDP_PASS;
    __u64 *stats_cntr;
    __u32 stats_key;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct packet_meta pckt = {0};
    struct vip_meta    vip = {0};
    struct lpm_key  key = {0};

    nh_off = sizeof(struct ethhdr);

    if (data + nh_off > data_end) {
        action = XDP_DROP;
        goto ret;
    }

    eth_proto = bpf_ntohs(eth->h_proto);

#ifdef VLAN

#pragma unroll
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

    pckt.l3_proto = eth_proto;
    if (eth_proto == ETH_P_IP) {
        action = process_header(&pckt, &pckt.l4_proto, nh_off, &pckt.l4_size, data, data_end);
    } else {
        goto ret;
    }

    if (action > 0) {
        goto ret;
    }

    __builtin_memcpy(key.address, &pckt.src, sizeof(key.address));
    key.prefixlen = 32;

    if (bpf_map_lookup_elem(&v4_blacklist, &key)) {
        action = XDP_DROP;
        stats_key = STAT_V4_BLACKLIST_HIT;
        stats_cntr = bpf_map_lookup_elem(&hit_counter, &stats_key);
        if (stats_cntr) {
            stats_cntr += 1;
        }
        goto ret;
    }

    if (pckt.l4_proto == IPPROTO_TCP) {
        action = parse_tcp(data, data_end, &ip_off, &pckt);
    } else if (pckt.l4_proto == IPPROTO_UDP) {
        action = parse_udp(data, data_end, &ip_off, &pckt);
    } else {
        action = XDP_PASS;
        goto ret;
    }

    if (action >0) {
        goto ret;
    }

    bpf_print("vip now: src:%d, dst:%d, sport:%d, dport:%d\n", pckt.src, pckt.dst, pckt.sport, pckt.dport);

    pckt.pkt_len = data_end - data;
    pckt.data_len = data_end - data - ip_off;
    if (bpf_perf_event_output(ctx, &perf_map,(__u64)pckt.pkt_len << 32 | BPF_F_CURRENT_CPU, &pckt, sizeof(pckt))) {
        bpf_print("perf_event_output failed: pkt_len:%d, data_len:%d\n", pckt.pkt_len, pckt.data_len);
    }

ret:
    return update_action_stats(pckt.pkt_len, action);
}

char _license[] SEC("license") = "GPL";
