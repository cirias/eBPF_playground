// +build ignore

/* #include <asm/types.h> */
/* #include <asm/byteorder.h> */

#include <linux/bpf.h>
/* #include <linux/filter.h> */
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
/* #include <linux/tcp.h> */

/* #include <bpf/bpf.h> */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* #include "helpers.h" */

struct tuple {
  __u32 packets;
  __u32 bytes;
};

#define BPF_MAP_ID_STATS 0 /* agent's map identifier */
#define BPF_MAX_ELEM     8

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, BPF_MAX_ELEM);
	/* __uint(pinning, LIBBPF_PIN_BY_NAME); */
} map_stats SEC(".maps");

SEC("tc") int cls_main(struct __sk_buff *skb)
{
  struct tuple *tu;
  __u8 ip_proto;
  __u32 key = 2;

  if (skb->protocol != __bpf_constant_htons(ETH_P_IP))
    return 0;

  if (bpf_skb_load_bytes_relative(skb, offsetof(struct iphdr, protocol),
        &ip_proto, sizeof(ip_proto), BPF_HDR_START_NET) < 0)
    return 0;

  if (ip_proto == IPPROTO_TCP) {
    key = 0;
  } else if (ip_proto == IPPROTO_UDP) {
    key = 1;
  }

  tu = bpf_map_lookup_elem(&map_stats, &key);
  if (tu) {
    __sync_fetch_and_add(&tu->packets, 1);
    __sync_fetch_and_add(&tu->bytes, skb->len);
  }

  return 0;
}

char __license[] SEC("license") = "GPL";
