// xdp_whitelist_kern.c

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>   // ← اضافه شده برای bpf_ntohs()

// تعریف BPF map برای whitelist IPها
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} whitelist_ips SEC(".maps");

// تابع اصلی XDP
SEC("xdp")
int xdp_whitelist(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end)
        return XDP_ABORTED;

    __u32 src_ip = ip->saddr;

    __u8 *found = bpf_map_lookup_elem(&whitelist_ips, &src_ip);
    if (!found)
        return XDP_DROP;

    return XDP_PASS;
}

// ← این نسخه درست کار می‌کنه
char _license[] SEC("license") = "GPL";
