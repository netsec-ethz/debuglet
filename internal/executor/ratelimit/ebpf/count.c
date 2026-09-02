//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TCX_PASS
#define TCX_PASS 0
#define TCX_DROP 2
#endif

// TCX_NEXT (== TC_ACT_UNSPEC) means "no verdict from this program, run the
// next one". A program returning TCX_PASS *terminates* the TCX chain, so any
// program attached after this one on the same hook — notably the packet
// accountability tagger in internal/executor/tagger/ebpf — would never run.
// This program only counts and rate-limits, so it must hand accepted packets
// on with TCX_NEXT and reserve a terminal verdict for drops. TCX_NEXT from
// the last program in the chain accepts the packet.
#ifndef TCX_NEXT
#define TCX_NEXT -1
#endif

#define NS_PER_SEC (1000000000ULL)
#define MAX_BURST_BYTES (65536ULL)

struct tb_state {
  __u64 tokens;
  __u64 t_last;
  struct bpf_spin_lock lock;
};

struct debuglet_key {
  __u8 uuid[16];
  __u8 ipv6[16];
} __attribute__((packed));

// Per-destination token bucket map
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct debuglet_key);
  __type(value, struct tb_state);
  __uint(max_entries, 10000);
} packet_size_map SEC(".maps");

// Per-destination rate limiting map
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct debuglet_key);
  __type(value, __u64);
  __uint(max_entries, 10000);
} rates_map SEC(".maps");

struct exec_key {
  __u8 uuid[16];
} __attribute__((packed));

// Executor-wide token bucket map
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct exec_key);
  __type(value, struct tb_state);
  __uint(max_entries, 10000);
} exec_packet_size_map SEC(".maps");

// Executor-wide rate limiting maps
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct exec_key);
  __type(value, __u64);
  __uint(max_entries, 10000);
} exec_rates_map SEC(".maps");

struct debuglet_uuid {
  __u8 uuid[16];
} __attribute__((packed));

// Maps socket ID to debuglet UUID
struct {
  __uint(type, BPF_MAP_TYPE_SK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct debuglet_uuid);
} debuglet_sk_map SEC(".maps");

// Returns the transport protocol number and sets *transport to the transport header pointer.
// Returns 0 if the chain is too long, encrypted (ESP), or a non-first fragment.
// Caller must check: return value must be IPPROTO_TCP or IPPROTO_UDP.
static __always_inline __u8 ipv6_walk_ext_headers(struct ipv6hdr *ip6, void *data_end,
                                                  void **transport_out) {
  __u8 nh = ip6->nexthdr;
  void *ptr = (void *)(ip6 + 1);

  // perform at most 8 hops
  for (int i = 0; i < 8; i++) {
    if (ptr + 8 > data_end)
      return 0;

    switch (nh) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_DSTOPTS:
      nh = *(__u8 *)ptr;
      ptr += (*(__u8 *)(ptr + 1) + 1) * 8;
      break;

    case IPPROTO_FRAGMENT:
      if (*(__be16 *)(ptr + 2) & __bpf_constant_htons(0xFFF8))
        return 0;
      nh = *(__u8 *)ptr;
      ptr += 8;
      break;

    case IPPROTO_AH:
      nh = *(__u8 *)ptr;
      ptr += (*(__u8 *)(ptr + 1) + 2) * 4;
      break;

    case IPPROTO_ESP:
      return 0;

    default:
      *transport_out = ptr;
      return nh;
    }
  }
  return 0;
}

// Returns NULL if no matching socket is found. Caller must bpf_sk_release() the result.
static __always_inline struct bpf_sock *lookup_ingress_sk(
    struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *ip,
    struct ipv6hdr *ip6, void *data_end) {

  __u8 ipproto;
  void *transport_hdr;

  if (eth->h_proto == __bpf_constant_htons(ETH_P_IP)) {
    if ((void *)(ip + 1) > data_end)
      return NULL;
    ipproto = ip->protocol;
    transport_hdr = (void *)(ip + 1);
  } else if (eth->h_proto == __bpf_constant_htons(ETH_P_IPV6)) {
    if ((void *)(ip6 + 1) > data_end)
      return NULL;
    ipproto = ipv6_walk_ext_headers(ip6, data_end, &transport_hdr);
    if (ipproto == 0)
      return NULL;
  } else {
    return NULL;
  }

  if (ipproto != IPPROTO_TCP && ipproto != IPPROTO_UDP)
    return NULL;

  if (ipproto == IPPROTO_TCP) {
    struct tcphdr *tcp = transport_hdr;
    if ((void *)(tcp + 1) > data_end)
      return NULL;

    if (eth->h_proto == __bpf_constant_htons(ETH_P_IP)) {
      struct bpf_sock_tuple tuple = {};
      tuple.ipv4.saddr = ip->saddr;
      tuple.ipv4.daddr = ip->daddr;
      tuple.ipv4.sport = tcp->source;
      tuple.ipv4.dport = tcp->dest;
      return bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    } else {
      struct bpf_sock_tuple tuple = {};
      __builtin_memcpy(tuple.ipv6.saddr, &ip6->saddr, sizeof(tuple.ipv6.saddr));
      __builtin_memcpy(tuple.ipv6.daddr, &ip6->daddr, sizeof(tuple.ipv6.daddr));
      tuple.ipv6.sport = tcp->source;
      tuple.ipv6.dport = tcp->dest;
      return bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv6), BPF_F_CURRENT_NETNS, 0);
    }
  } else { /* IPPROTO_UDP */
    struct udphdr *udp = transport_hdr;
    if ((void *)(udp + 1) > data_end)
      return NULL;

    if (eth->h_proto == __bpf_constant_htons(ETH_P_IP)) {
      struct bpf_sock_tuple tuple = {};
      tuple.ipv4.saddr = ip->saddr;
      tuple.ipv4.daddr = ip->daddr;
      tuple.ipv4.sport = udp->source;
      tuple.ipv4.dport = udp->dest;
      return bpf_sk_lookup_udp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    } else {
      struct bpf_sock_tuple tuple = {};
      __builtin_memcpy(tuple.ipv6.saddr, &ip6->saddr, sizeof(tuple.ipv6.saddr));
      __builtin_memcpy(tuple.ipv6.daddr, &ip6->daddr, sizeof(tuple.ipv6.daddr));
      tuple.ipv6.sport = udp->source;
      tuple.ipv6.dport = udp->dest;
      return bpf_sk_lookup_udp(skb, &tuple, sizeof(tuple.ipv6), BPF_F_CURRENT_NETNS, 0);
    }
  }
}

int limit_packets(struct __sk_buff *skb, int is_ingress) {
  struct debuglet_uuid *uuid = NULL;

  if (!is_ingress) {
    if (!skb->sk)
      return TCX_NEXT;
    uuid = bpf_sk_storage_get(&debuglet_sk_map, skb->sk, 0, 0);
    if (!uuid)
      return TCX_NEXT;
  }

  // =========== BUILD DEBUGLET KEY {ip,uuid} ===========

  struct debuglet_key key = {};

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TCX_NEXT;

  struct iphdr *ip = NULL;
  struct ipv6hdr *ip6 = NULL;

  if (eth->h_proto == __bpf_constant_htons(ETH_P_IP)) {
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
      return TCX_NEXT;

    key.ipv6[10] = 0xff;
    key.ipv6[11] = 0xff;
    if (is_ingress) {
      *(__u32 *)&key.ipv6[12] = ip->saddr;
    } else {
      *(__u32 *)&key.ipv6[12] = ip->daddr;
    }

  } else if (eth->h_proto == __bpf_constant_htons(ETH_P_IPV6)) {
    ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
      return TCX_NEXT;

    if (is_ingress) {
      __builtin_memcpy(key.ipv6, &ip6->saddr, sizeof(key.ipv6));
    } else {
      __builtin_memcpy(key.ipv6, &ip6->daddr, sizeof(key.ipv6));
    }

  } else {
    return TCX_NEXT;
  }

  struct bpf_sock *looked_up_sk = NULL;
  int action = TCX_NEXT;
  // --- INGRESS: look up socket via 5-tuple ---
  if (is_ingress) {
    looked_up_sk = lookup_ingress_sk(skb, eth, ip, ip6, data_end);
    if (looked_up_sk)
      uuid = bpf_sk_storage_get(&debuglet_sk_map, looked_up_sk, 0, 0);
  }

  if (!uuid)
    goto release;

  __builtin_memcpy(key.uuid, uuid->uuid, sizeof(uuid->uuid));

  // =========== CHECK WHITELIST RATELIMIT ===========

  __u64 *rate = bpf_map_lookup_elem(&rates_map, &key);
  if (!rate) {
    action = TCX_DROP;
    goto release;
  }

  // =========== PER-DESTINATION TOKEN BUCKET ===========

  __u64 now = bpf_ktime_get_ns();
  struct tb_state new_state = {.t_last = now, .tokens = MAX_BURST_BYTES};
  bpf_map_update_elem(&packet_size_map, &key, &new_state, BPF_NOEXIST);

  struct tb_state *state = bpf_map_lookup_elem(&packet_size_map, &key);
  if (!state) {
    action = TCX_DROP;
    goto release;
  }

  bpf_spin_lock(&state->lock);
  __u64 delta_ns = now - state->t_last;
  __u64 new_tokens = (*rate) * delta_ns / NS_PER_SEC;
  state->tokens += new_tokens;
  if (state->tokens > MAX_BURST_BYTES)
    state->tokens = MAX_BURST_BYTES;

  if (state->tokens >= skb->len) {
    state->tokens -= skb->len;
    state->t_last = now;
  } else {
    action = TCX_DROP;
  }
  __u32 diag_len = skb->len;
  __u64 diag_tokens = state->tokens;
  __u64 diag_rate = *rate;
  __u32 diag_segs = skb->gso_segs ? skb->gso_segs : 1;
  __u32 diag_seglen = skb->gso_size;
  bpf_spin_unlock(&state->lock);

  if (action == TCX_DROP) {
    bpf_printk("Rate limit exceeded, dropping packet len=%d tokens=%llu rate=%llu segs=%d seglen=%d",
               diag_len, diag_tokens, diag_rate, diag_segs, diag_seglen);
    goto release;
  }

  // =========== EXECUTOR-WIDE TOKEN BUCKET ===========

  struct exec_key ekey = {};
  __builtin_memcpy(ekey.uuid, uuid->uuid, sizeof(uuid->uuid));
  __u64 *exec_rate = bpf_map_lookup_elem(&exec_rates_map, &ekey);
  if (!exec_rate) {
    action = TCX_DROP;
    goto release;
  }

  struct tb_state exec_new_state = {.t_last = now, .tokens = MAX_BURST_BYTES};
  bpf_map_update_elem(&exec_packet_size_map, &ekey, &exec_new_state, BPF_NOEXIST);

  struct tb_state *exec_state = bpf_map_lookup_elem(&exec_packet_size_map, &ekey);
  if (!exec_state) {
    action = TCX_DROP;
    goto release;
  }

  bpf_spin_lock(&exec_state->lock);
  __u64 exec_new_tokens = (*exec_rate) * delta_ns / NS_PER_SEC;
  exec_state->tokens += exec_new_tokens;
  if (exec_state->tokens > MAX_BURST_BYTES)
    exec_state->tokens = MAX_BURST_BYTES;
  if (exec_state->tokens < skb->len) {
    bpf_spin_unlock(&exec_state->lock);
    action = TCX_DROP;
    goto release;
  }
  exec_state->tokens -= skb->len;
  exec_state->t_last = now;
  bpf_spin_unlock(&exec_state->lock);

release:
  if (looked_up_sk)
    bpf_sk_release(looked_up_sk);
  return action;
}

SEC("tcx/egress")
int handle_egress(struct __sk_buff *skb) {
  return limit_packets(skb, 0);
}

SEC("tcx/ingress")
int handle_ingress(struct __sk_buff *skb) {
  return limit_packets(skb, 1);
}

char __license[] SEC("license") = "Dual MIT/GPL";
