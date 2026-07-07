//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/ptrace.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TCX_PASS
#define TCX_PASS 0
#define TCX_DROP 2
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

int limit_packets(struct __sk_buff *skb, int is_ingress) {
  if (!skb->sk)
    return TCX_PASS;
  struct debuglet_uuid *uuid = bpf_sk_storage_get(&debuglet_sk_map, skb->sk, 0, 0);

  if (!uuid)
    return TCX_PASS;

  bpf_printk("UUID = %x:%x...", uuid->uuid[0], uuid->uuid[1]);

  // =========== BUILD DEBUGLET KEY {ip,uuid} ===========

  struct debuglet_key key = {};
  __builtin_memcpy(key.uuid, uuid->uuid, sizeof(uuid->uuid));

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TCX_PASS;

  if (eth->h_proto == __bpf_constant_htons(ETH_P_IP)) {
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
      return TCX_PASS;

    key.ipv6[10] = 0xff;
    key.ipv6[11] = 0xff;
    if (is_ingress) {
      *(__u32 *)&key.ipv6[12] = ip->saddr;
    } else {
      *(__u32 *)&key.ipv6[12] = ip->daddr;
    }

  } else if (eth->h_proto == __bpf_constant_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
      return TCX_PASS;

    if (is_ingress) {
      __builtin_memcpy(key.ipv6, &ip6->saddr, sizeof(key.ipv6));
    } else {
      __builtin_memcpy(key.ipv6, &ip6->daddr, sizeof(key.ipv6));
    }

  } else {
    return TCX_PASS;
  }

  // =========== CHECK WHITELIST RATELIMIT ===========

  __u64 *rate = bpf_map_lookup_elem(&rates_map, &key);
  if (!rate)
    return TCX_DROP;

  // =========== PER-DESTINATION TOKEN BUCKET ===========

  __u64 now = bpf_ktime_get_ns();
  struct tb_state new_state = {.t_last = now, .tokens = MAX_BURST_BYTES};
  bpf_map_update_elem(&packet_size_map, &key, &new_state, BPF_NOEXIST);

  struct tb_state *state = bpf_map_lookup_elem(&packet_size_map, &key);
  if (!state)
    return TCX_DROP;

  int action = TCX_PASS;
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
    return TCX_DROP;
  }

  // =========== EXECUTOR-WIDE TOKEN BUCKET ===========

  struct exec_key ekey = {};
  __builtin_memcpy(ekey.uuid, uuid->uuid, sizeof(uuid->uuid));
  __u64 *exec_rate = bpf_map_lookup_elem(&exec_rates_map, &ekey);
  if (!exec_rate)
    return TCX_DROP;

  struct tb_state exec_new_state = {.t_last = now, .tokens = MAX_BURST_BYTES};
  bpf_map_update_elem(&exec_packet_size_map, &ekey, &exec_new_state, BPF_NOEXIST);

  struct tb_state *exec_state = bpf_map_lookup_elem(&exec_packet_size_map, &ekey);
  if (!exec_state)
    return TCX_DROP;

  bpf_spin_lock(&exec_state->lock);
  __u64 exec_new_tokens = (*exec_rate) * delta_ns / NS_PER_SEC;
  exec_state->tokens += exec_new_tokens;
  if (exec_state->tokens > MAX_BURST_BYTES)
    exec_state->tokens = MAX_BURST_BYTES;
  if (exec_state->tokens < skb->len) {
    bpf_spin_unlock(&exec_state->lock);
    return TCX_DROP;
  }
  exec_state->tokens -= skb->len;
  exec_state->t_last = now;
  bpf_spin_unlock(&exec_state->lock);

  return TCX_PASS;
}

SEC("tcx/egress")
int handle_egress(struct __sk_buff *skb) {
  return limit_packets(skb, 0);
}

char __license[] SEC("license") = "Dual MIT/GPL";
