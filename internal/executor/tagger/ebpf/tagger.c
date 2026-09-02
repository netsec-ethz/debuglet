//go:build ignore
// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich
//
// eBPF TC egress program for debuglet packet accountability tagging.
//
// This program is attached to the TC egress hook on the host interface via
// the cilium/ebpf Go library. For every outgoing IPv4 packet it:
//
//  1. Reads the current per-measurement authentication key (ak) from a BPF map.
//  2. Computes a 16-bit keyed SipHash-2-4 tag over the full packet.
//  3. Writes the tag into the IPv4 Identification (IPID) field (bytes 4-5).
//  4. Recomputes the IPv4 header checksum.
//
// NOTE: Full HMAC-SHA256 is not available inside the BPF verifier. We use
// SipHash-2-4 as a fast, keyed pseudo-random function that is BPF-safe.
// The Go-layer tagger uses HMAC-SHA256 for comparison purposes.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// TCX_NEXT (== TC_ACT_UNSPEC) means "no verdict, run the next program on this
// hook". Returning TC_ACT_OK here would terminate the TCX chain and silently
// disable every program attached after this one (e.g. the rate limiter in
// internal/executor/ratelimit/ebpf). This program only rewrites a header
// field, so it always hands the packet on. TCX_NEXT from the last program in
// the chain accepts the packet.
#ifndef TCX_NEXT
#define TCX_NEXT -1
#endif

// Maximum number of concurrent measurements tracked.
#define MAX_MEASUREMENTS 256

// AK entry stored in the BPF map — 128-bit (16-byte) authentication key.
// The Go side writes the full 32-byte HMAC key; we use the first 16 bytes as
// the two 64-bit SipHash key words.
struct ak_entry {
    __u64 k0;
    __u64 k1;
};

// Map: measurement_id_hash (u32) → ak_entry
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MEASUREMENTS);
    __type(key, __u32);
    __type(value, struct ak_entry);
} ak_map SEC(".maps");

// ---------------------------------------------------------------------------
// SipHash-2-4 (inline, BPF-safe)
// Reference: https://131002.net/siphash/siphash.pdf
// ---------------------------------------------------------------------------

#define SIPROUND(v0,v1,v2,v3) do { \
    v0 += v1; v1 = (v1<<13)|(v1>>51); v1 ^= v0; v0 = (v0<<32)|(v0>>32); \
    v2 += v3; v3 = (v3<<16)|(v3>>48); v3 ^= v2; \
    v0 += v3; v3 = (v3<<21)|(v3>>43); v3 ^= v0; \
    v2 += v1; v1 = (v1<<17)|(v1>>47); v1 ^= v2; v2 = (v2<<32)|(v2>>32); \
} while(0)

// Compute SipHash-2-4 over at most 64 bytes of data (eBPF stack limit).
// Returns a 64-bit hash; caller truncates to 16 bits.
static __always_inline __u64 siphash24(__u64 k0, __u64 k1,
                                        const __u8 *data, __u32 len) {
    __u64 v0 = k0 ^ 0x736f6d6570736575ULL;
    __u64 v1 = k1 ^ 0x646f72616e646f6dULL;
    __u64 v2 = k0 ^ 0x6c7967656e657261ULL;
    __u64 v3 = k1 ^ 0x7465646279746573ULL;

    // Process 8-byte blocks (up to 64 bytes to stay within BPF stack).
    __u32 blocks = (len < 64 ? len : 64) / 8;

#pragma unroll
    for (__u32 i = 0; i < 8; i++) {
        if (i >= blocks) break;
        __u64 m = 0;
        __builtin_memcpy(&m, data + i * 8, 8);
        v3 ^= m;
        SIPROUND(v0, v1, v2, v3);
        SIPROUND(v0, v1, v2, v3);
        v0 ^= m;
    }

    // Finalisation.
    __u64 b = ((__u64)len) << 56;
    v3 ^= b;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

// ---------------------------------------------------------------------------
// Main TC egress program
// ---------------------------------------------------------------------------

SEC("tc/egress")
int debuglet_tag(struct __sk_buff *skb) {
    // 1. Fast path: check socket mark to immediately bypass untagged traffic
    __u32 map_key = skb->mark;
    if (map_key == 0)
        return TCX_NEXT;

    // 2. Perform map lookup only for marked packets
    struct ak_entry *ak = bpf_map_lookup_elem(&ak_map, &map_key);
    if (!ak)
        return TCX_NEXT;

    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr  *iph;
    __u32 off;

    // Determine if we have an Ethernet header or raw IP.
    if ((void *)(eth + 1) <= data_end && bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        off = sizeof(struct ethhdr);
        iph = (void *)(eth + 1);
    } else {
        iph = data;
        off = 0;
    }

    // Safety check for IP header access.
    if ((void *)(iph + 1) > data_end || iph->version != 4)
        return TCX_NEXT;

    // Compute SipHash over the IP header + first 56 bytes of payload.
    __u8 buf[64] = {};
    __u32 pkt_len = skb->len;
    if (pkt_len < off)
        return TCX_NEXT;
    pkt_len -= off;

    __u32 copy_len = pkt_len;
    if (copy_len > 64)
        copy_len = 64;
    if (copy_len == 0)
        return TCX_NEXT;

    // BPF Verifier trick: force the range to [1, 64] to avoid "invalid zero-sized read"
    // and satisfy scalar tracking.
    copy_len = ((copy_len - 1) & 63) + 1;

    if (bpf_skb_load_bytes(skb, off, buf, copy_len) < 0)
        return TCX_NEXT;

    // Canonical form: zero mutable IP header fields before hashing (IPID at 4-5, checksum at 10-11).
    if (copy_len >= 12) {
        buf[4] = 0;
        buf[5] = 0;
        buf[10] = 0;
        buf[11] = 0;
    }

    __u64 hash = siphash24(ak->k0, ak->k1, buf, copy_len);
    __u16 tag  = (__u16)(hash & 0xFFFF);

    // Write tag into IPID field (offset 4 from start of IP header).
    __u32 ipid_off = off + offsetof(struct iphdr, id);
    __be16 old_id = 0;
    bpf_skb_load_bytes(skb, ipid_off, &old_id, 2);

    __be16 tag_be = bpf_htons(tag);
    __u32 csum_off = off + offsetof(struct iphdr, check);
    if (bpf_l3_csum_replace(skb, csum_off, old_id, tag_be, 2) < 0) {
        return TCX_NEXT;
    }

    if (bpf_skb_store_bytes(skb, ipid_off, &tag_be, sizeof(tag_be), 0) < 0) {
        bpf_printk("tagger: bpf_skb_store_bytes failed at off=%d\n", ipid_off);
        return TCX_NEXT;
    }

    return TCX_NEXT;
}

char _license[] SEC("license") = "Dual MIT/GPL";
