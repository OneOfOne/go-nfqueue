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
	uint16_t sport, dport;

	int len = nfq_get_payload(nfa, &payload);

	if(len <= 0 || len <=  sizeof(struct iphdr)) {
		return 0;
	}

	struct iphdr * ip = (struct iphdr *) payload;
	if(ip->version == 4) {
		saddr = (unsigned char *)&ip->saddr;
		daddr = (unsigned char *)&ip->daddr;
		if(ip->protocol == IPPROTO_TCP) {
			//stuff
		} else if(ip->protocol == IPPROTO_UDP) {

		}
	} else {
		struct ipv6hdr *ip6 = (struct ipv6hdr*) payload;
		saddr = (unsigned char *)&ip->saddr;
		daddr = (unsigned char *)&ip->daddr;
		//ipv6
	}

	int verdict = go_nfq_callback(ip->version, ip->protocol, saddr, daddr, 0, 0, NULL, data);
	return nfq_set_verdict(qh, id, verdict, 0, NULL);
	//go_callback(ip->version, ip->protocol, saddr, daddr, sport, dport, extra-payload?, data)

}
