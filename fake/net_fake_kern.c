#include "net_fake_common.h"

__attribute__((__always_inline__))
static inline int handle_syn_packet(struct packet_meta *pckt, void *data, void *data_end, __u32 cookie)
{
    __u8 tmp_addr[6];
    __u32 ipaddr = 0;
    __u32 tcpport = 0;
    struct ethhdr *eth = data + pckt->eth_off;
    struct iphdr *ipv4 = data + pckt->ip_off;
    struct tcphdr *tcp = data + pckt->tcp_off;

    // swap mac
    __builtin_memcpy(&tmp_addr, &eth->h_source, sizeof(tmp_addr));
    __builtin_memcpy(&eth->h_dest, &eth->h_source, sizeof(tmp_addr));
    __builtin_memcpy(&tmp_addr, &eth->h_dest, sizeof(tmp_addr));

    // swap ip
    ipaddr = ipv4->saddr;
    ipv4->saddr = ipv4->daddr;
    ipv4->daddr = ipaddr;

    tcp->ack_seq = tcp->seq + 1;
    tcp->seq = cookie;
    tcp->ack = 1;

    // swap port
    tcpport = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tcpport;

    return XDP_TX;
}

__attribute__((__always_inline__))
static inline int handle_ack_packet(struct packet_meta *pckt, void *data, void *data_end)
{
    __u8 online = 1;
    __u8 tmp_addr[6];
    __u32 ipaddr = 0;
    __u32 tcpport = 0;
    __u32 seq = 0;
    struct ethhdr *eth = data + pckt->eth_off;
    struct iphdr *ipv4 = data + pckt->ip_off;
    struct tcphdr *tcp = data + pckt->tcp_off;

#ifdef TABLE
    struct conn_meta conn;
    // update connection table
    conn.dst = pckt->dst;
    conn.src = pckt->src;
    conn.ports = pckt->ports;
    bpf_map_update_elem(&conn_map, &conn, &online, BPF_ANY);
#endif

    // swap mac
    __builtin_memcpy(&tmp_addr, &eth->h_source, sizeof(tmp_addr));
    __builtin_memcpy(&eth->h_dest, &eth->h_source, sizeof(tmp_addr));
    __builtin_memcpy(&tmp_addr, &eth->h_dest, sizeof(tmp_addr));

    // swap ip
    ipaddr =ipv4->saddr;
    ipv4->saddr = ipv4->daddr;
    ipv4->daddr = ipaddr;

    seq = tcp->seq;
    tcp->seq = tcp->ack_seq;
    tcp->ack_seq = seq + 1;
    tcp->ack = 1;
    tcp->syn = 0;

    // swap port
    tcpport = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tcpport;

    return XDP_TX;
}

__attribute__((__always_inline__))
static inline __u32 calc_cookie(struct packet_meta *pckt) {
    __u32 auth = 0;

    auth = pckt->port16[0] << 16;
    auth |= pckt->port16[1];
    auth ^= pckt->src;
    auth ^= pckt->dst;

    return auth;
}

__attribute__((__always_inline__))
static inline int handle_tcp(struct packet_meta *pckt, void *data, void *data_end)
{
    __u8 *online;
    struct tcphdr *tcp;
    struct target_meta target;
#ifdef TABLE
    struct conn_meta conn;
#endif

    tcp = data + pckt->tcp_off;
    if (tcp + 1 > data_end) {
        return XDP_DROP;
    }

    pckt->port16[0] = bpf_ntohs(tcp->source);
    pckt->port16[1] = bpf_ntohs(tcp->dest);
    pckt->seq   = tcp->seq;

#ifdef TABLE
    conn.dst = pckt->dst;
    conn.src = pckt->src;
    conn.ports = pckt->ports;

    online = bpf_map_lookup_elem(&conn_map, &conn);
    if (online && *online == 1) {
        return XDP_PASS;
    }

#endif

    target.dst = pckt->dst;
    target.dport = pckt->port16[1];
    if (!bpf_map_lookup_elem(&target_map, &target)) {
        target.dst = 0;
        if (!bpf_map_lookup_elem(&target_map, &target)) {
            bpf_print("target is not hit, dst:%u, port:%u\n", pckt->dst, pckt->port16[1]);
            return XDP_PASS;
        }
    }

    __u32 cookie = calc_cookie(pckt);

#ifdef TABLE
    if ((tcp->syn == 1 && tcp->ack == 1) || tcp->res1 == 1 || tcp->cwr == 1 ||  tcp->ece == 1 || tcp->urg == 1 ||
            tcp->psh == 1 || tcp->rst == 1 || tcp->fin == 1) {
        bpf_print("drop packet, src:%u, dst:%u, port:%u\n", pckt->src, pckt->dst, pckt.port16[1]);
        return XDP_DROP;
    } else if (tcp->syn == 1) {
        return handle_syn_packet(pckt, data, data_end, cookie);
    } else if ( (tcp->ack == 1) && ((tcp->ack_seq - 1) == cookie)) {
        return handle_ack_packet(pckt, data, data_end);
    }
#else
    if ((tcp->syn == 1 && tcp->ack == 1) || tcp->res1 == 1 || tcp->cwr == 1 ||  tcp->ece == 1 || tcp->urg == 1 ||
            tcp->psh == 1 || tcp->rst == 1 || tcp->fin == 1) {
        return -1;
    } else if (tcp->syn == 1) {
        return handle_syn_packet(pckt, data, data_end, cookie);
    } else if ( (tcp->ack == 1) && ((tcp->ack_seq - 1) == cookie)) {
        return handle_ack_packet(pckt, data, data_end);
    }
#endif

    return XDP_DROP;
}

__attribute__((__always_inline__))
static inline int process_header(struct packet_meta *pckt, __u8 *protocol, __u32 off,
                                     __u16 *pkt_bytes, void *data, void *data_end)
{
    struct iphdr *iph;

    iph = data + off;
    if (iph + 1 > data_end) {
        return XDP_DROP;
    }

    if (iph->ihl != 5) {
        bpf_print("ihl is not 5\n");
        return XDP_DROP;
    }

    *protocol = iph->protocol;
    *pkt_bytes = bpf_ntohs(iph->tot_len);
    off += IPV4_HDR_LEN_NO_OPT;

    pckt->src = iph->saddr;
    pckt->dst = iph->daddr;
    return -1;
}

SEC("netfake")
int net_fake(struct xdp_md *ctx)
{
    __u16 pkt_bytes;
    __u32 nh_off = 0;
    __u32 eth_proto = 0;
    __u32 action = XDP_PASS;
    __u32 sample_size = 0;
    int  result = 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct packet_meta pckt = {0};

    nh_off = sizeof(struct ethhdr);

    if (data + nh_off > data_end) {
        action = XDP_DROP;
        goto ret;
    }
    eth_proto = bpf_ntohs(eth->h_proto);

    if (eth_proto == ETH_P_IP) {
        result = process_header(&pckt, &pckt.l4_proto, nh_off, &pkt_bytes, data, data_end);
        if (result > 0) {
            goto ret;
        }
    }

    if (pckt.l4_proto == IPPROTO_TCP) {
        pckt.eth_off = 0;
        pckt.ip_off += nh_off;
        nh_off += sizeof(struct iphdr);
        pckt.tcp_off += nh_off;

        pckt.pkt_len = data_end - data;
        pckt.data_len = pckt.pkt_len - nh_off;

        result = handle_tcp(&pckt, data, data_end);
        if (result > 0) {
            action = result;
            goto ret;
        }

        sample_size = MIN(pckt.pkt_len, MAX_SAMPLE_SIZE);
        bpf_perf_event_output(ctx, &dump_map,(__u64)sample_size << 32 | BPF_F_CURRENT_CPU, &pckt, sizeof(struct packet_meta));
    }

ret:
    return action;
}


char _license[] SEC("license") = "GPL";
