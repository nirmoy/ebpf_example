#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))
__section("prog")
int xdp_drop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr  *ip  = data + sizeof(*eth);

	if (data + sizeof(*eth) > data_end)
		return XDP_DROP;

	if (NTOHS(eth->h_proto) != (ETH_P_IP))
		return XDP_PASS;

	if((void*)( ip + 1) > data_end)
		return XDP_PASS;

	if (ip->protocol == IPPROTO_ICMP) {
		unsigned char   temp[ETH_ALEN];
		unsigned int temp_ip;
		
		__builtin_memcpy(temp, eth->h_dest, ETH_ALEN);
		__builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
		__builtin_memcpy(eth->h_source, temp,ETH_ALEN);
		
		temp_ip = NTOHL(ip->saddr);
		ip->saddr = ip->daddr;
		ip->daddr = HTONL(temp_ip);

		struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
		if((void*)( icmp + 1) > data_end)
			return XDP_PASS;
		icmp->type = 0;
		return XDP_TX;
	}

	return XDP_PASS;
}

char __license[] __section("license") = "GPL";

