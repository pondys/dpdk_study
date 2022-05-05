#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <arpa/inet.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#include "review.h"


#define NUMBUFS  (8191)
#define BURST_SIZE (32)

#define MAKE_IP(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
#define TIMER_RESOLUTION_CYCLES 40000000000ULL


static uint32_t gLocalIp = MAKE_IP(192, 168, 0, 109);
//ether mac 00; arp mac ff
static uint8_t gDefaultArpLclMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static uint32_t gSrcIp;
static uint32_t gDstIp;
static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];
static uint16_t gSrcPort;
static uint16_t gDstPort;

uint16_t gDpdkPortId = 0;
uint16_t gRTxNbDesc = 1024;

static const struct rte_eth_conf gPortConfDefault = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

static struct ys_arp_table *gArp = NULL;

#if 1  //basic
static void ys_port_init(struct rte_mempool *mbuf_pool)
{
    uint16_t ys_sys_ports = 0;
	struct rte_eth_dev_info dev_info;
	uint16_t ys_rx_q = 1;
	uint16_t ys_tx_q = 1;
	struct rte_eth_conf ys_dev_conf = gPortConfDefault;
	struct rte_eth_txconf ys_tx_conf;

    //准备信息
	ys_sys_ports = rte_eth_dev_count_avail();
	if (0 == ys_sys_ports)
	{
	    rte_exit(EXIT_FAILURE, "Error in dev_count_avail.\n");
	}
	rte_eth_dev_info_get(gDpdkPortId, &dev_info);
	rte_eth_dev_configure(gDpdkPortId, ys_rx_q, ys_tx_q, &ys_dev_conf);

	//队列建立
	if (0 > rte_eth_rx_queue_setup(gDpdkPortId, 0, gRTxNbDesc, 
		rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool))
	{
	    rte_exit(EXIT_FAILURE, "Error in rx_queue_setup.\n");
	}

    ys_tx_conf = dev_info.default_txconf;
	ys_tx_conf.offloads = ys_dev_conf.rxmode.offloads;
	if (0 > rte_eth_tx_queue_setup(gDpdkPortId, 0, gRTxNbDesc, 
		rte_eth_dev_socket_id(gDpdkPortId), &ys_tx_conf))
	{
	    rte_exit(EXIT_FAILURE, "Error in tx_queue_setup.\n");
	}

	if (0 > rte_eth_dev_start(gDpdkPortId))
	{
	    rte_exit(EXIT_FAILURE, "Error in dev_start.\n");
	}

	return;
}

#endif

#if 1  //udp
static void ys_udp_pkt_encode(uint8_t *udp_total_data, uint8_t *msg_data, uint16_t total_len)
{
    struct in_addr t_addr;
	struct rte_ether_hdr *eth = NULL;
	struct rte_ipv4_hdr *ip = NULL;
	struct rte_udp_hdr *udp = NULL;
	uint16_t udplen = 0;

	//1 ethhdr
    eth = (struct rte_ether_hdr *)udp_total_data;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    //2 iphdr
    ip = (struct rte_ipv4_hdr *)(udp_total_data + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = gSrcIp;
    ip->dst_addr = gDstIp;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    //3 udphdr
    udp = (struct rte_udp_hdr *)(udp_total_data + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = gSrcPort;
    udp->dst_port = gDstPort;
    udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);

    rte_memcpy((uint8_t*)(udp + 1), msg_data, (udplen - sizeof(struct rte_udp_hdr)));
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);


	t_addr.s_addr = ip->dst_addr;
	printf("send udp remote: %s:%d, ", inet_ntoa(t_addr), ntohs(udp->dst_port));

	t_addr.s_addr = ip->src_addr;
	printf("from: %s:%d, data(%d): %s\n", inet_ntoa(t_addr), ntohs(udp->src_port), 
						udplen, (char *)(udp + 1));

	return;
}

static struct rte_mbuf *ys_udp_alloc(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t udp_len)
{
    struct rte_mbuf *mbuf = NULL;
	const unsigned length = udp_len + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
	uint8_t *udp_data = NULL;

	mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (NULL == mbuf)
	{
	    rte_exit(EXIT_FAILURE, "Error in udp alloc.\n");
	}
	mbuf->data_len = length;
	mbuf->pkt_len = length;

	//encode
	udp_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
	ys_udp_pkt_encode(udp_data, data, length);

	return mbuf;
}

#endif

#if 1  //arp
static void ys_arp_pkt_encode(uint8_t *msg, uint16_t opcode, 
										uint8_t *dst_mac, uint32_t sip, uint32_t dip)
{
    struct rte_ether_hdr *ehdr = (struct rte_ether_hdr *)msg;
	struct rte_arp_hdr *ahdr = (struct rte_arp_hdr *)(ehdr + 1);
	uint8_t lcl_mac[RTE_ETHER_ADDR_LEN] = {0x0};

	//ether
	ehdr->ether_type = htons(RTE_ETHER_TYPE_ARP);
	rte_memcpy(ehdr->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);

	if (0 == strncmp((const char*)dst_mac, (const char*)gDefaultArpLclMac, RTE_ETHER_ADDR_LEN))
	{
        rte_memcpy(ehdr->d_addr.addr_bytes, lcl_mac, RTE_ETHER_ADDR_LEN);
	}
	else
	{
	    rte_memcpy(ehdr->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}

	//arp
	ahdr->arp_hardware = htons(1);
	ahdr->arp_hlen = RTE_ETHER_ADDR_LEN;
	ahdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	ahdr->arp_plen = sizeof(uint32_t);
	ahdr->arp_opcode = htons(opcode);

	rte_memcpy(ahdr->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ahdr->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	ahdr->arp_data.arp_sip = sip;
	ahdr->arp_data.arp_tip = dip;

	return;
}

static struct rte_mbuf *ys_arp_alloc(struct rte_mempool *mbuf_pool, uint16_t opcode, 
											uint8_t *dst_mac, uint32_t sip, uint32_t dip)
{
    struct rte_mbuf *mbuf = NULL;
	const unsigned length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	uint8_t *arp_data = NULL;

	mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (NULL == mbuf)
	{
	    rte_exit(EXIT_FAILURE, "Error in arp alloc.\n");
	}
	mbuf->data_len = length;
	mbuf->pkt_len = length;

	//encode
	arp_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
	ys_arp_pkt_encode(arp_data, opcode, dst_mac, sip, dip);

	return mbuf;
}

//arp表单例
static struct ys_arp_table *ys_arp_table_get(void)
{
	if (NULL == gArp)
	{
	    gArp = rte_malloc("arp_table", sizeof(struct ys_arp_table), 0);
		if (NULL == gArp)
		{
		    rte_exit(EXIT_FAILURE, "Error in arp table get.\n");
		}
		memset(gArp, 0, sizeof(struct ys_arp_table));
	}
	return gArp;
}

//arp表mac地址匹配
static uint8_t* ys_arp_dst_macaddr_get(uint32_t dip)
{
    struct ys_arp_entry *iter = NULL;
	struct ys_arp_table *arp_table = ys_arp_table_get();

	for (iter = arp_table->entries; iter != NULL; iter = iter->next)
	{
	    if (dip == iter->ip)
	    {
	        return iter->hwaddr;
	    }
	}
    return NULL;
}

//定时发送arp request到指定ip
static void ys_arp_timer_callback(__attribute__((unused)) struct rte_timer *tm, void *arg)
{
    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct rte_mbuf *arp_req_buf = NULL;
	uint32_t dip = 0;
	uint8_t *dmac = NULL;
	struct in_addr t_addr;

	for (int i = 105; i < 120; i++)
	{
	    dip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));
		t_addr.s_addr = dip;
		printf("send arp req remote: %s \n", inet_ntoa(t_addr));

		dmac = ys_arp_dst_macaddr_get(dip);
		if (NULL == dmac)
		{
		    arp_req_buf = ys_arp_alloc(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpLclMac, gLocalIp, dip);
		}
		else
		{
	        arp_req_buf = ys_arp_alloc(mbuf_pool, RTE_ARP_OP_REQUEST, dmac, gLocalIp, dip);
		}

		rte_eth_tx_burst(gDpdkPortId, 0, &arp_req_buf, 1);
		rte_pktmbuf_free(arp_req_buf);
	}

	return;
}

static void ys_arp_timer_init(struct rte_mempool *mbuf_pool)
{
    struct rte_timer arp_timer;
	uint64_t t_hz = 0;
	unsigned lcore_id = 0;

	rte_timer_subsystem_init();
	rte_timer_init(&arp_timer);
	t_hz = rte_get_timer_hz();
    lcore_id = rte_lcore_id();

	rte_timer_reset(&arp_timer, t_hz, PERIODICAL, lcore_id, ys_arp_timer_callback, mbuf_pool);

    return;
}

static inline void ys_print_ether_addr(const char *what, const struct rte_ether_addr *eth_addr)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", what, buf);
}

#endif

#if 1  //icmp
static uint16_t ys_checksum(uint16_t *addr, int count) {

	register long sum = 0;

	while (count > 1) {

		sum += *(unsigned short*)addr++;
		count -= 2;
	
	}

	if (count > 0) {
		sum += *(unsigned char *)addr;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

static void ys_icmp_pkt_encode(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, 
										uint32_t dip, uint16_t id, uint16_t seqnb)
{
    struct rte_ether_hdr *ehdr = (struct rte_ether_hdr *)msg;
	struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(ehdr + 1);
	struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

	//ether
	ehdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	rte_memcpy(ehdr->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(ehdr->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	//ipv4
	iphdr->version_ihl = 0x45;
	iphdr->type_of_service = 0;
	iphdr->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
	iphdr->packet_id = 0;
	iphdr->fragment_offset = 0;
	iphdr->time_to_live = 64;
	iphdr->next_proto_id = IPPROTO_ICMP;
	iphdr->src_addr = sip;
	iphdr->dst_addr = dip;

	iphdr->hdr_checksum = 0;
	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

	//icmp
	icmphdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
	icmphdr->icmp_code = 0;
	icmphdr->icmp_ident = id;
	icmphdr->icmp_seq_nb = seqnb;

	icmphdr->icmp_cksum = 0;
	icmphdr->icmp_cksum = ys_checksum((uint16_t*)icmphdr, sizeof(struct rte_icmp_hdr));

	return;
}

static struct rte_mbuf *ys_icmp_alloc(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, 
											uint32_t dip, uint16_t id, uint16_t seqnb)
{
    struct rte_mbuf *mbuf = NULL;
	const unsigned length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 
							sizeof(struct rte_icmp_hdr);
	uint8_t *icmp_data = NULL;

	mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (NULL == mbuf)
	{
	    rte_exit(EXIT_FAILURE, "Error in icmp alloc.\n");
	}
	mbuf->data_len = length;
	mbuf->pkt_len = length;

	//encode
	icmp_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
	ys_icmp_pkt_encode(icmp_data, dst_mac, sip, dip, id, seqnb);

	return mbuf;
}
#endif

int32_t main(int argc, char* argv[])
{
    struct rte_mempool *mbuf_pool = NULL;
	unsigned i = 0;
	struct rte_mbuf *mbuf[BURST_SIZE];
	unsigned recv_nb = 0;
	struct rte_mbuf *abuf = NULL;
	struct rte_mbuf *icmpbuf = NULL;
	uint8_t *hwaddr = NULL;
	uint16_t udp_len = 0;
	struct rte_mbuf *udpbuf = NULL;
	
	struct ys_arp_table *t_arp_table = NULL;
	struct ys_arp_entry *t_entry = NULL;
	struct ys_arp_entry *iter = NULL;

	struct rte_ether_hdr *ehdr = NULL;
	struct rte_arp_hdr *ahdr = NULL;
	struct rte_ipv4_hdr *iphdr = NULL;
	struct rte_icmp_hdr *icmphdr = NULL;
	struct rte_udp_hdr *udphdr = NULL;

	struct in_addr t_addr;
	static uint64_t prev_tsc = 0, cur_tsc;
	uint64_t diff_tsc = 0;

	//环境初始化
	if(rte_eal_init(argc, argv) < 0)
	{
	    rte_exit(EXIT_FAILURE, "Error in init.\n");
	}

	//内存池准备
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NUMBUFS, 0, 0, 
										RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (NULL == mbuf_pool)
	{
	    rte_exit(EXIT_FAILURE, "Error in pool create.\n");
	}

	//端口初始化
	ys_port_init(mbuf_pool);

	//本地mac获取
	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr*)gSrcMac);

	//定时器初始化
	ys_arp_timer_init(mbuf_pool);

	while (1)
	{
	    recv_nb = rte_eth_rx_burst(gDpdkPortId, 0, mbuf, BURST_SIZE);
		if (recv_nb > BURST_SIZE)
		{
		    rte_exit(EXIT_FAILURE, "Error in rx_burst.\n");
		}

		for (i = 0; i < recv_nb; i++)
		{
		    //先解析eth头
		    ehdr = rte_pktmbuf_mtod(mbuf[i], struct rte_ether_hdr *);
			if (rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP) == ehdr->ether_type)
			{
				ahdr = rte_pktmbuf_mtod_offset(mbuf[i], struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

				if (gLocalIp == ahdr->arp_data.arp_tip)
				{
				    if (rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) == ahdr->arp_opcode)
				    {
					    t_addr.s_addr = ahdr->arp_data.arp_tip;
						printf("recv arp req local: %s, ", inet_ntoa(t_addr));

						t_addr.s_addr = ahdr->arp_data.arp_sip;
						printf("from: %s \n", inet_ntoa(t_addr));

						//封装arp rsp并发出
						abuf = ys_arp_alloc(mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes, 
											ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
						rte_eth_tx_burst(gDpdkPortId, 0, &abuf, 1);
						rte_pktmbuf_free(abuf);
				    }
					else if (rte_cpu_to_be_16(RTE_ARP_OP_REPLY) == ahdr->arp_opcode)
					{
					    t_addr.s_addr = ahdr->arp_data.arp_tip;
						printf("recv arp reply local: %s, ", inet_ntoa(t_addr));

						t_addr.s_addr = ahdr->arp_data.arp_sip;
						printf("from: %s \n", inet_ntoa(t_addr));

						//遍历查找
						t_arp_table = ys_arp_table_get();
						hwaddr = ys_arp_dst_macaddr_get(ahdr->arp_data.arp_sip);
						if (NULL == hwaddr)
						{
						    t_entry = rte_malloc("ys arp entry", sizeof(struct ys_arp_entry), 0);
							if (NULL == t_entry)
							{
							    rte_exit(EXIT_FAILURE, "Error in entry alloc.\n");
							}
							memset(t_entry, 0x0, sizeof(struct ys_arp_entry));

							t_entry->type = ARP_TYPE_DYNAMIC;
							t_entry->ip = ahdr->arp_data.arp_sip;
							rte_memcpy(t_entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);

							L_H_ADD(t_entry, t_arp_table->entries);
							t_arp_table->count++;
						}

						//debug
						for (iter = t_arp_table->entries; iter != NULL; iter = iter->next)
						{
						    ys_print_ether_addr("arp entry --> mac: ", (struct rte_ether_addr *)iter->hwaddr);
							t_addr.s_addr = iter->ip;
							printf("ip: %s \n", inet_ntoa(t_addr));
						}
					}
				}
			}

			//只处理ipv4
			if (rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) != ehdr->ether_type)
			{
			    goto next;
			}

			iphdr = rte_pktmbuf_mtod_offset(mbuf[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
			if (IPPROTO_UDP == iphdr->next_proto_id)
			{
			    udphdr = (struct rte_udp_hdr *)(iphdr + 1);

				gSrcPort = udphdr->dst_port;
				gDstPort = udphdr->src_port;
				rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
				gSrcIp = iphdr->dst_addr;
				gDstIp = iphdr->src_addr;

				udp_len = ntohs(udphdr->dgram_len);
				*((char*)udphdr + udp_len) = '\0';

                //print
				t_addr.s_addr = iphdr->dst_addr;
				printf("recv udp local: %s:%d, ", inet_ntoa(t_addr), ntohs(udphdr->dst_port));

				t_addr.s_addr = iphdr->src_addr;
				printf("from: %s:%d, data(%d): %s\n", inet_ntoa(t_addr), ntohs(udphdr->src_port), 
						udp_len, (char *)(udphdr + 1));

                if (iphdr->src_addr == MAKE_IP(192, 168, 0, 108))
                {
					//封装udp rsp并发出
					udpbuf = ys_udp_alloc(mbuf_pool, (uint8_t *)(udphdr + 1), udp_len);
					rte_eth_tx_burst(gDpdkPortId, 0, &udpbuf, 1);
					rte_pktmbuf_free(udpbuf);
                }
			}

			if (IPPROTO_ICMP == iphdr->next_proto_id)
			{
			    icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
				if (RTE_IP_ICMP_ECHO_REQUEST == icmphdr->icmp_type && 
					gLocalIp == iphdr->dst_addr)
				{
					t_addr.s_addr = iphdr->dst_addr;
					printf("recv icmp req local: %s, ", inet_ntoa(t_addr));

					t_addr.s_addr = iphdr->src_addr;
					printf("from: %s \n", inet_ntoa(t_addr));

					//封装icmp rsp并发出
					icmpbuf = ys_icmp_alloc(mbuf_pool, ehdr->s_addr.addr_bytes, iphdr->dst_addr, 
											iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
					rte_eth_tx_burst(gDpdkPortId, 0, &icmpbuf, 1);
					rte_pktmbuf_free(icmpbuf);
				}
			}

next:
			rte_pktmbuf_free(mbuf[i]);
		}

		//timer start
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}

	return 0;
}
