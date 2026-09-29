//go:build ignore
// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich
//
// eBPF TC egress program for debuglet packet accountability tagging.
//
// This program is attached to the TC egress hook on the host interface via
// the cilium/ebpf Go library. It implements the packet tag of
// docs/tag-spec.md, version debuglet-tag-v1. For every outgoing unfragmented
// IPv4 packet of a marked socket it:
//
//  1. Reads the current per-measurement authentication key (ak) from a BPF map.
//  2. Builds the canonical tag input: the first min(64, total length) bytes
//     with TOS, IP ID, flags/fragment offset, TTL, header checksum, IP options
//     and the ICMP/TCP/UDP checksum zeroed.
//  3. Computes standard SipHash-2-4 keyed with ak[0:16] over that input and
//     keeps the low 16 bits as the tag.
//  4. Writes the tag into the IPv4 Identification field, sets DF and updates
//     the IPv4 header checksum incrementally.
//
// Packets v1 does not tag (fragments, malformed or short headers) pass
// unchanged. The pure-Go tagger (tesla.HashInput, tesla.PacketTag) computes
// the same tag; testdata/tag-vectors-v1.json pins both.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// TCX_NEXT (== TC_ACT_UNSPEC) means "no verdict, run the next program on this
// hook". Returning TC_ACT_OK here would terminate the TCX chain and silently
// disable every program attached after this one (e.g. the rate limiter in
// internal/executor/ratelimit/ebpf). This program only rewrites header
// fields, so it always hands the packet on. TCX_NEXT from the last program in
// the chain accepts the packet.
#ifndef TCX_NEXT
#define TCX_NEXT -1
#endif

// Maximum number of concurrent measurements tracked.
#define MAX_MEASUREMENTS 256

// Most packet bytes the tag authenticates (tesla.MaxTagInput).
#define TAG_INPUT_MAX 64

// AK entry stored in the BPF map — 128-bit (16-byte) authentication key.
// The Go side writes the first 16 bytes of the 32-byte derived key ak as two
// little-endian 64-bit words, the standard SipHash key encoding.
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
// SipHash-2-4 (standard, BPF-safe)
// Reference: Aumasson and Bernstein, "SipHash: a fast short-input PRF", 2012.
// ---------------------------------------------------------------------------

#define SIPROUND(v0,v1,v2,v3) do { \
    v0 += v1; v1 = (v1<<13)|(v1>>51); v1 ^= v0; v0 = (v0<<32)|(v0>>32); \
    v2 += v3; v3 = (v3<<16)|(v3>>48); v3 ^= v2; \
    v0 += v3; v3 = (v3<<21)|(v3>>43); v3 ^= v0; \
    v2 += v1; v1 = (v1<<17)|(v1>>47); v1 ^= v2; v2 = (v2<<32)|(v2>>32); \
} while(0)

// SipHash-2-4 over the first len bytes of buf (1 <= len <= 64). buf holds
// TAG_INPUT_MAX bytes and is zero after len, so the final word is the 8-byte
// word holding the trailing len%8 bytes with len in its top byte.
static __always_inline __u64 siphash24(__u64 k0, __u64 k1,
                                        const __u8 *buf, __u32 len) {
    __u64 v0 = k0 ^ 0x736f6d6570736575ULL;
    __u64 v1 = k1 ^ 0x646f72616e646f6dULL;
    __u64 v2 = k0 ^ 0x6c7967656e657261ULL;
    __u64 v3 = k1 ^ 0x7465646279746573ULL;
    __u32 blocks = len / 8;
    __u64 last = ((__u64)len) << 56;

#pragma unroll
    for (__u32 i = 0; i < TAG_INPUT_MAX / 8; i++) {
        __u64 m = 0;
        __builtin_memcpy(&m, buf + i * 8, 8);
        if (i == blocks) {
            // Bytes after len are zero, so the whole word is the tail.
            last |= m;
            break;
        }
        v3 ^= m;
        SIPROUND(v0, v1, v2, v3);
        SIPROUND(v0, v1, v2, v3);
        v0 ^= m;
    }

    v3 ^= last;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    v0 ^= last;
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

    __u32 ihl   = iph->ihl * 4;
    __u32 total = bpf_ntohs(iph->tot_len);
    __u8  proto = iph->protocol;
    // Malformed headers and fragments (MF or a fragment offset) carry no v1
    // tag; their IP ID must stay as the sender chose it.
    if (ihl < sizeof(struct iphdr) || total < ihl)
        return TCX_NEXT;
    if (bpf_ntohs(iph->frag_off) & 0x3fff)
        return TCX_NEXT;

    __u32 pkt_len = skb->len;
    if (pkt_len < off)
        return TCX_NEXT;
    pkt_len -= off;

    __u32 n = total < TAG_INPUT_MAX ? total : TAG_INPUT_MAX;
    if (pkt_len < n)
        return TCX_NEXT;
    // n >= 20 here; the mask tells the verifier the load stays in [1, 64].
    n = ((n - 1) & (TAG_INPUT_MAX - 1)) + 1;

    __u8 buf[TAG_INPUT_MAX] = {};
    if (bpf_skb_load_bytes(skb, off, buf, n) < 0)
        return TCX_NEXT;

    // Canonical input: zero the fields a router, NAT or offload rewrites.
    buf[1] = 0;                 // TOS: DSCP and ECN
    buf[4] = 0; buf[5] = 0;     // IP ID
    buf[6] = 0; buf[7] = 0;     // flags and fragment offset
    buf[8] = 0;                 // TTL
    buf[10] = 0; buf[11] = 0;   // header checksum
#pragma unroll
    for (__u32 i = sizeof(struct iphdr); i < TAG_INPUT_MAX; i++) {
        if (i >= ihl || i >= n)
            break;
        buf[i] = 0;             // IP options
    }
    __u32 csum = 0;
    if (proto == 1)
        csum = ihl + 2;         // ICMP
    else if (proto == 6)
        csum = ihl + 16;        // TCP
    else if (proto == 17)
        csum = ihl + 6;         // UDP
    if (csum) {
        if (csum < n)
            buf[csum & (TAG_INPUT_MAX - 1)] = 0;
        if (csum + 1 < n)
            buf[(csum + 1) & (TAG_INPUT_MAX - 1)] = 0;
    }

    __u64 hash = siphash24(ak->k0, ak->k1, buf, n);
    __u16 tag  = (__u16)(hash & 0xFFFF);

    // Write the tag into the IP ID and set DF: bytes 4-7 of the IP header
    // change together, with one incremental checksum update.
    __u32 word_off = off + offsetof(struct iphdr, id);
    __u8 old_word[4];
    if (bpf_skb_load_bytes(skb, word_off, old_word, 4) < 0)
        return TCX_NEXT;
    __u8 new_word[4] = {
        (__u8)(tag >> 8), (__u8)(tag & 0xff), (__u8)(old_word[2] | 0x40), old_word[3],
    };
    __u32 from, to;
    __builtin_memcpy(&from, old_word, 4);
    __builtin_memcpy(&to, new_word, 4);

    __u32 csum_off = off + offsetof(struct iphdr, check);
    if (bpf_l3_csum_replace(skb, csum_off, from, to, 4) < 0)
        return TCX_NEXT;
    if (bpf_skb_store_bytes(skb, word_off, new_word, 4, 0) < 0) {
        bpf_printk("tagger: bpf_skb_store_bytes failed at off=%d\n", word_off);
        return TCX_NEXT;
    }

    return TCX_NEXT;
}

char _license[] SEC("license") = "Dual MIT/GPL";
