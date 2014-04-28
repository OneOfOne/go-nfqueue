#include "nfqueue.h"
#include "_cgo_export.h"


int nfqueue_cb_new(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {

	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);

	if(ph == NULL) {
		return 1;
	}
	
	int id =  ntohl(ph->packet_id);
	
	unsigned char * payload;
	unsigned char * saddr, * daddr;
	uint16_t sport = 0,  dport = 0, checksum = 0;
	uint32_t mark = nfq_get_nfmark(nfa);

	int len = nfq_get_payload(nfa, &payload);

	if(len <= 0 || len <=  sizeof(struct iphdr)) {
		return 0;
	}

	struct iphdr * ip = (struct iphdr *) payload;
	if(ip->version == 4) {
		saddr = (unsigned char *)&ip->saddr;
		daddr = (unsigned char *)&ip->daddr;

		if(ip->protocol == IPPROTO_TCP) {
			struct tcphdr *tcp = ((struct tcphdr *) (payload + (ip->ihl << 2)));
			sport = ntohs(tcp->source);
			dport = ntohs(tcp->dest);
			checksum = ntohs(tcp->check);
		} else if(ip->protocol == IPPROTO_UDP) {
			struct udphdr *u = ((struct udphdr *) (payload + (ip->ihl << 2)));
			sport = ntohs(u->source);
			dport = ntohs(u->dest);
			checksum = ntohs(u->check);
		}
	} else {
		struct ipv6hdr *ip6 = (struct ipv6hdr*) payload;
		saddr = (unsigned char *)&ip6->saddr;
		daddr = (unsigned char *)&ip6->daddr;
		//ipv6
	}
	//pass everything we can and let Go handle it, I'm not a big fan of C
	uint32_t verdict = go_nfq_callback(id, ntohs(ph->hw_protocol), ph->hook, &mark, ip->version, ip->protocol, 
								  ip->tos, ip->ttl, saddr, daddr, sport, dport, checksum, payload, data);
	return nfq_set_verdict2(qh, id, verdict, mark, 0, NULL);
}

void loop_for_packets(struct nfq_handle *h) {
	int fd = nfq_fd(h);
	char buf[4096] __attribute__ ((aligned));
	int rv;
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) { 
		nfq_handle_packet(h, buf, rv); 
	}
}
