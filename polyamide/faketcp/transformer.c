//go:build ignore

// SPDX-License-Identifier: Apache-2.0

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#else
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_ntohl(x) (x)
#endif

#define TCX_NEXT -1
#define TCX_DROP 2
#define BPF_F_RECOMPUTE_CSUM 1
#define BPF_CSUM_LEVEL_RESET 3

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define CARRIER_MAGIC 0x4e59
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_ACK 0x10

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	union {
		void *flow_keys;
		__u64 flow_keys_align;
	};
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
};

static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset,
				    const void *from, __u32 len, __u64 flags) = (void *)9;
static long (*bpf_skb_pull_data)(struct __sk_buff *skb, __u32 len) = (void *)39;
static long (*bpf_csum_level)(struct __sk_buff *skb, __u64 level) = (void *)135;

struct eth_header {
	__u8 destination[6];
	__u8 source[6];
	__be16 protocol;
} __attribute__((packed));

struct ipv4_header {
	__u8 version_ihl;
	__u8 tos;
	__be16 total_length;
	__be16 id;
	__be16 fragment_offset;
	__u8 ttl;
	__u8 protocol;
	__be16 checksum;
	__be32 source;
	__be32 destination;
} __attribute__((packed));

struct ipv6_header {
	__be32 version_flow;
	__be16 payload_length;
	__u8 next_header;
	__u8 hop_limit;
	__u8 source[16];
	__u8 destination[16];
} __attribute__((packed));

struct udp_carrier {
	__be16 source;
	__be16 destination;
	__be16 length;
	__be16 checksum;
	__be16 magic;
	__be16 meta;
	__be32 sequence;
	__be32 acknowledgement;
} __attribute__((packed));

struct tcp_header {
	__be16 source;
	__be16 destination;
	__be32 sequence;
	__be32 acknowledgement;
	__u8 data_offset;
	__u8 flags;
	__be16 window;
	__be16 checksum;
	__be16 urgent;
} __attribute__((packed));

struct packet_info {
	__u16 l4_offset;
	__u16 l4_length;
	__u8 version;
	__u8 protocol;
	__u8 standard;
};

const volatile __u16 managed_port = 0;

static __always_inline __u32 add_be16(__u32 sum, __be16 value)
{
	return sum + bpf_ntohs(value);
}

static __always_inline __u32 add_be32(__u32 sum, __be32 value)
{
	__u32 host = bpf_ntohl(value);
	return sum + (host >> 16) + (host & 0xffff);
}

static __always_inline __u32 subtract_be16(__u32 sum, __be16 value)
{
	return sum + ((~bpf_ntohs(value)) & 0xffff);
}

static __always_inline __u32 subtract_be32(__u32 sum, __be32 value)
{
	__u32 host = bpf_ntohl(value);
	return sum + ((~(host >> 16)) & 0xffff) + ((~host) & 0xffff);
}

static __always_inline __be16 finish_checksum(__u32 sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	__u16 checksum = ~sum;
	if (checksum == 0)
		checksum = 0xffff;
	return bpf_htons(checksum);
}

static __always_inline int parse_packet(struct __sk_buff *skb,
					void *data, void *data_end,
					struct packet_info *info)
{
	struct eth_header *ethernet = data;
	if ((void *)(ethernet + 1) > data_end)
		return 0;

	if (ethernet->protocol == bpf_htons(ETH_P_IP)) {
		struct ipv4_header *ip = data + sizeof(*ethernet);
		if ((void *)(ip + 1) > data_end || ip->version_ihl >> 4 != 4)
			return 0;
		__u8 ihl = (ip->version_ihl & 0xf) * 4;
		__u16 total_length = bpf_ntohs(ip->total_length);
		if (ihl < sizeof(*ip) || total_length < ihl ||
		    sizeof(*ethernet) + total_length > skb->len)
			return 0;
		info->l4_offset = sizeof(*ethernet) + ihl;
		info->l4_length = total_length - ihl;
		info->version = 4;
		info->protocol = ip->protocol;
		info->standard = ihl == sizeof(*ip) &&
			(bpf_ntohs(ip->fragment_offset) & 0x3fff) == 0;
		return 1;
	}

	if (ethernet->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6_header *ip = data + sizeof(*ethernet);
		if ((void *)(ip + 1) > data_end ||
		    bpf_ntohl(ip->version_flow) >> 28 != 6)
			return 0;
		__u16 payload_length = bpf_ntohs(ip->payload_length);
		if (sizeof(*ethernet) + sizeof(*ip) + payload_length > skb->len)
			return 0;
		info->l4_offset = sizeof(*ethernet) + sizeof(*ip);
		info->l4_length = payload_length;
		info->version = 6;
		info->protocol = ip->next_header;
		info->standard = 1;
		return 1;
	}

	return 0;
}

static __always_inline __be16 ipv4_checksum(struct ipv4_header *ip)
{
	__u32 sum = ((__u32)ip->version_ihl << 8) + ip->tos;
	sum = add_be16(sum, ip->total_length);
	sum = add_be16(sum, ip->id);
	sum = add_be16(sum, ip->fragment_offset);
	sum += ((__u32)ip->ttl << 8) + ip->protocol;
	sum = add_be32(sum, ip->source);
	sum = add_be32(sum, ip->destination);
	return finish_checksum(sum);
}

static __always_inline __u32 tcp_header_sum(struct tcp_header *tcp, __u32 sum)
{
	sum = add_be16(sum, tcp->source);
	sum = add_be16(sum, tcp->destination);
	sum = add_be32(sum, tcp->sequence);
	sum = add_be32(sum, tcp->acknowledgement);
	sum += ((__u32)tcp->data_offset << 8) + tcp->flags;
	sum = add_be16(sum, tcp->window);
	sum = add_be16(sum, tcp->urgent);
	return sum;
}

static __always_inline __u32 subtract_tcp_header(struct tcp_header *tcp,
						  __u32 sum)
{
	sum = subtract_be16(sum, tcp->source);
	sum = subtract_be16(sum, tcp->destination);
	sum = subtract_be32(sum, tcp->sequence);
	sum = subtract_be32(sum, tcp->acknowledgement);
	sum += (~(((__u32)tcp->data_offset << 8) + tcp->flags)) & 0xffff;
	sum = subtract_be16(sum, tcp->window);
	sum = subtract_be16(sum, tcp->urgent);
	return sum;
}

static __always_inline __u32 carrier_header_sum(struct udp_carrier *carrier,
						  __u32 sum)
{
	sum = add_be16(sum, carrier->source);
	sum = add_be16(sum, carrier->destination);
	sum = add_be16(sum, carrier->length);
	sum = add_be16(sum, carrier->magic);
	sum = add_be16(sum, carrier->meta);
	sum = add_be32(sum, carrier->sequence);
	sum = add_be32(sum, carrier->acknowledgement);
	return sum;
}

static __always_inline __be16 tcp_checksum(void *data,
					    struct packet_info *info,
					    struct tcp_header *tcp,
					    __u32 payload_sum,
					    __be16 option_word_one,
					    __be16 option_word_two)
{
	__u32 sum = payload_sum + IPPROTO_TCP + info->l4_length;
	if (info->version == 4) {
		struct ipv4_header *ip = data + sizeof(struct eth_header);
		sum = add_be32(sum, ip->source);
		sum = add_be32(sum, ip->destination);
	} else {
		struct ipv6_header *ip = data + sizeof(struct eth_header);
#pragma unroll
		for (int i = 0; i < 16; i += 2) {
			sum += ((__u32)ip->source[i] << 8) + ip->source[i + 1];
			sum += ((__u32)ip->destination[i] << 8) + ip->destination[i + 1];
		}
	}
	sum = tcp_header_sum(tcp, sum);
	sum = add_be16(sum, option_word_one);
	sum = add_be16(sum, option_word_two);
	return finish_checksum(sum);
}

static __always_inline int update_ip_protocol(struct __sk_buff *skb,
					       struct packet_info *info,
					       __u8 protocol,
					       struct ipv4_header *ipv4)
{
	if (info->version == 4) {
		ipv4->protocol = protocol;
		ipv4->checksum = 0;
		ipv4->checksum = ipv4_checksum(ipv4);
		return bpf_skb_store_bytes(skb, sizeof(struct eth_header), ipv4,
					   sizeof(*ipv4), BPF_F_RECOMPUTE_CSUM);
	}
	return bpf_skb_store_bytes(skb,
				   sizeof(struct eth_header) + 6,
				   &protocol, sizeof(protocol), BPF_F_RECOMPUTE_CSUM);
}

SEC("tcx/egress")
int fake_tcp_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct eth_header *ethernet = data;
	if ((void *)(ethernet + 1) > data_end)
		return TCX_NEXT;
	if (ethernet->protocol == bpf_htons(ETH_P_IP)) {
		if (data + sizeof(*ethernet) + sizeof(struct ipv4_header) > data_end) {
			if (bpf_skb_pull_data(skb, sizeof(*ethernet) +
					       sizeof(struct ipv4_header)) < 0)
				return TCX_NEXT;
			data = (void *)(long)skb->data;
			data_end = (void *)(long)skb->data_end;
		}
	} else if (ethernet->protocol == bpf_htons(ETH_P_IPV6)) {
		if (data + sizeof(*ethernet) + sizeof(struct ipv6_header) > data_end) {
			if (bpf_skb_pull_data(skb, sizeof(*ethernet) +
					       sizeof(struct ipv6_header)) < 0)
				return TCX_NEXT;
			data = (void *)(long)skb->data;
			data_end = (void *)(long)skb->data_end;
		}
	} else {
		return TCX_NEXT;
	}
	struct packet_info info = {};
	if (!parse_packet(skb, data, data_end, &info) || info.protocol != IPPROTO_UDP ||
	    info.l4_length < sizeof(struct udp_carrier))
		return TCX_NEXT;
	__u32 pull_length = info.l4_offset + sizeof(struct tcp_header);
	if (info.l4_length >= sizeof(struct tcp_header) + 4)
		pull_length += 4;
	if (pull_length > sizeof(struct eth_header) + 60 +
			  sizeof(struct tcp_header) + 4)
		return TCX_NEXT;
	if (data + pull_length > data_end) {
		if (bpf_skb_pull_data(skb, pull_length) < 0)
			return TCX_NEXT;
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;
	}

	struct udp_carrier *carrier = data + info.l4_offset;
	if ((void *)(carrier + 1) > data_end ||
	    carrier->magic != bpf_htons(CARRIER_MAGIC) || carrier->checksum != 0)
		return TCX_NEXT;
	if (bpf_ntohs(carrier->source) != managed_port)
		return TCX_NEXT;

	if (!info.standard || skb->gso_segs > 1 ||
	    bpf_ntohs(carrier->length) != info.l4_length)
		return TCX_DROP;

	struct tcp_header tcp = {
		.source = carrier->source,
		.destination = carrier->destination,
		.sequence = carrier->sequence,
		.acknowledgement = carrier->acknowledgement,
		.data_offset = 0x50,
		.flags = TCP_FLAG_ACK,
		.window = bpf_htons(0xffff),
	};
	__u32 payload_sum = 0;
	__be16 option_one = 0;
	__be16 option_two = 0;

	__u16 meta = bpf_ntohs(carrier->meta);
	if (info.l4_length == sizeof(struct udp_carrier) + 4) {
		__u8 *option = data + info.l4_offset + sizeof(struct udp_carrier);
		if ((meta == TCP_FLAG_SYN || meta == (TCP_FLAG_SYN | TCP_FLAG_ACK)) &&
		    option + 4 <= (__u8 *)data_end && option[0] == 1 &&
		    option[1] == 3 && option[2] == 3 && option[3] == 14) {
			tcp.data_offset = 0x60;
			tcp.flags = meta;
			option_one = *(__be16 *)&option[0];
			option_two = *(__be16 *)&option[2];
		} else {
			payload_sum = meta;
		}
	} else if (info.l4_length == sizeof(struct udp_carrier)) {
		if (meta != TCP_FLAG_ACK)
			return TCX_DROP;
	} else {
		payload_sum = meta;
	}

	struct ipv4_header ipv4 = {};
	if (info.version == 4)
		ipv4 = *(struct ipv4_header *)(data + sizeof(struct eth_header));
	tcp.checksum = tcp_checksum(data, &info, &tcp, payload_sum,
				    option_one, option_two);
	if (bpf_skb_store_bytes(skb, info.l4_offset, &tcp, sizeof(tcp),
				BPF_F_RECOMPUTE_CSUM) < 0)
		return TCX_DROP;
	if (update_ip_protocol(skb, &info, IPPROTO_TCP, &ipv4) < 0)
		return TCX_DROP;
	return TCX_NEXT;
}

SEC("tcx/ingress")
int fake_tcp_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct eth_header *ethernet = data;
	if ((void *)(ethernet + 1) > data_end)
		return TCX_NEXT;
	if (ethernet->protocol == bpf_htons(ETH_P_IP)) {
		if (data + sizeof(*ethernet) + sizeof(struct ipv4_header) > data_end) {
			if (bpf_skb_pull_data(skb, sizeof(*ethernet) +
					       sizeof(struct ipv4_header)) < 0)
				return TCX_NEXT;
			data = (void *)(long)skb->data;
			data_end = (void *)(long)skb->data_end;
		}
	} else if (ethernet->protocol == bpf_htons(ETH_P_IPV6)) {
		if (data + sizeof(*ethernet) + sizeof(struct ipv6_header) > data_end) {
			if (bpf_skb_pull_data(skb, sizeof(*ethernet) +
					       sizeof(struct ipv6_header)) < 0)
				return TCX_NEXT;
			data = (void *)(long)skb->data;
			data_end = (void *)(long)skb->data_end;
		}
	} else {
		return TCX_NEXT;
	}
	struct packet_info info = {};
	if (!parse_packet(skb, data, data_end, &info) || info.protocol != IPPROTO_TCP ||
	    info.l4_length < sizeof(struct tcp_header))
		return TCX_NEXT;
	__u32 pull_length = info.l4_offset + sizeof(struct tcp_header);
	if (info.l4_length >= sizeof(struct tcp_header) + 4)
		pull_length += 4;
	if (pull_length > sizeof(struct eth_header) + 60 +
			  sizeof(struct tcp_header) + 4)
		return TCX_NEXT;
	if (data + pull_length > data_end) {
		if (bpf_skb_pull_data(skb, pull_length) < 0)
			return TCX_NEXT;
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;
	}

	struct tcp_header *wire_tcp = data + info.l4_offset;
	if ((void *)(wire_tcp + 1) > data_end ||
	    bpf_ntohs(wire_tcp->destination) != managed_port)
		return TCX_NEXT;
	if (!info.standard)
		return TCX_DROP;

	struct tcp_header tcp = *wire_tcp;
	__u32 header_length = tcp.data_offset >> 4;
	header_length *= 4;
	if ((tcp.data_offset & 0xf) != 0)
		return TCX_DROP;

	if (tcp.flags == TCP_FLAG_SYN ||
	    tcp.flags == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
		__u8 *option = data + info.l4_offset + sizeof(tcp);
		if (header_length != sizeof(tcp) + 4 ||
		    info.l4_length != header_length || option + 4 > (__u8 *)data_end ||
		    option[0] != 1 || option[1] != 3 || option[2] != 3 || option[3] != 14)
			return TCX_DROP;
	} else {
		if (header_length != sizeof(tcp))
			return TCX_DROP;
		if (info.l4_length == header_length) {
			if (tcp.flags != TCP_FLAG_ACK &&
			    tcp.flags != (TCP_FLAG_FIN | TCP_FLAG_ACK) &&
			    tcp.flags != TCP_FLAG_RST &&
			    tcp.flags != (TCP_FLAG_RST | TCP_FLAG_ACK))
				return TCX_DROP;
		} else if (tcp.flags != TCP_FLAG_ACK) {
			return TCX_DROP;
		}
	}

	struct udp_carrier carrier = {
		.source = tcp.source,
		.destination = tcp.destination,
		.length = bpf_htons(info.l4_length),
		.magic = bpf_htons(CARRIER_MAGIC),
		.meta = bpf_htons(tcp.flags),
		.sequence = tcp.sequence,
		.acknowledgement = tcp.acknowledgement,
	};
	if (skb->gso_segs <= 1) {
		__u32 sum = (~bpf_ntohs(tcp.checksum)) & 0xffff;
		sum = subtract_tcp_header(&tcp, sum);
		sum += (~IPPROTO_TCP) & 0xffff;
		sum = carrier_header_sum(&carrier, sum);
		sum += IPPROTO_UDP;
		carrier.checksum = finish_checksum(sum);
	}
	struct ipv4_header ipv4 = {};
	if (info.version == 4)
		ipv4 = *(struct ipv4_header *)(data + sizeof(struct eth_header));
	if (bpf_skb_store_bytes(skb, info.l4_offset, &carrier, sizeof(carrier),
				BPF_F_RECOMPUTE_CSUM) < 0)
		return TCX_DROP;
	if (update_ip_protocol(skb, &info, IPPROTO_UDP, &ipv4) < 0)
		return TCX_DROP;
	if (bpf_csum_level(skb, BPF_CSUM_LEVEL_RESET) < 0)
		return TCX_DROP;
	return TCX_NEXT;
}

char __license[] SEC("license") = "Apache-2.0";
