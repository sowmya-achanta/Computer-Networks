//============================================================================
// Name        : wiretap.cpp
// Author      : jmadagun
// Version     :
// Copyright   : NA
// Description : This program extracts packet headers from packets that are
//				 read from a save-file.
//============================================================================

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap/bpf.h>

#include <time.h>
#include <limits.h>
#include <string.h>
#include "wt_lib.h"

void initialize();
void packet_header_extract(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
u_int8_t handle_IP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
u_char* handle_ARP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
u_char* handle_TCP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
u_char* handle_UDP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
u_char* handle_ICMP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void display_help() {
	printf("\nSyntax:"
		"\n./wiretap --[Option] <File Name>\n"
		"\nOption\tUsage"
		"\n------\t------"
		"\nopen\topen <File Name>"
		"\nhelp\tDisplay Help"
		"\n");
}

int total_packets = 0;

u_int sum_packet_sizes = 0;
u_int min_packet_size = UINT_MAX;
u_int max_packet_size = 0;

ether_stat_t ether_stat_source[MAX_ARR_SIZE];
ether_stat_t ether_stat_dest[MAX_ARR_SIZE];
ether_type_list_t ether_type_list[10];
net_lyr_stat_t net_lyr_stat_source[MAX_ARR_SIZE];
net_lyr_stat_t net_lyr_stat_dest[MAX_ARR_SIZE];
arp_stat_t arp_stat[MAX_ARR_SIZE];
ipproto_type_list_t ipproto_type_list[10];
tran_lyr_stat_t tran_lyr_stat_tcp_source[MAX_ARR_SIZE];
tran_lyr_stat_t tran_lyr_stat_tcp_dest[MAX_ARR_SIZE];
tcp_flag_stat_t tcp_flag_stat_ack[MAX_ARR_SIZE];
tcp_flag_stat_t tcp_flag_stat_urg[MAX_ARR_SIZE];
tcp_flag_stat_t tcp_flag_stat_rst[MAX_ARR_SIZE];
tcp_flag_stat_t tcp_flag_stat_fin[MAX_ARR_SIZE];
tcp_flag_stat_t tcp_flag_stat_syn[MAX_ARR_SIZE];
tcp_flag_stat_t tcp_flag_stat_psh[MAX_ARR_SIZE];
tran_lyr_stat_t tran_lyr_stat_udp_source[MAX_ARR_SIZE];
tran_lyr_stat_t tran_lyr_stat_udp_dest[MAX_ARR_SIZE];
icmp_opt_t icmp_opt_type[MAX_ARR_SIZE];
icmp_opt_t icmp_opt_code[MAX_ARR_SIZE];
tcp_opt_t tcp_opt_stat[UCHAR_MAX + 1];

int main(int argc, char **argv) {
	char *fname;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* fp;
	u_char* args = NULL;
	clock_t begin_time, end_time;
	time_t curr_time;
	struct tm *loc_time;
	int i = 0, j = 0;
	int urg_cnt=0, ack_cnt=0, syn_cnt=0, fin_cnt=0, psh_cnt=0, rst_cnt=0, tcp_opt_cnt =0, icmp_type_cnt=0, icmp_code_cnt=0;

	initialize();

	// Check if input file is provided
	if (argc < 2 || argc > 3) {
		printf("Invalid Arguments\n");
		display_help();
		return 0;
	}

	if (argc == 2){
		if(strcmp(argv[1], "--help")!=0){
			printf("Invalid Arguments\n");
			display_help();
			return 0;
		}
	} else {
		if(strcmp(argv[1],"--open")!=0){
			printf("Invalid Arguments\n");
			display_help();
			return 0;
		}
	}

	if (strcmp(argv[1],"--help")==0){
		display_help();
		return 0;
	}

	// Calculate current time
	curr_time = time(NULL);
	loc_time = localtime(&curr_time);

	// Begin timer to calculate duration
	begin_time = clock();

	fname = argv[2];
	//puts(argv[2]);
	// Open the save file
	fp = pcap_open_offline(fname, errbuf);
	if (fp == NULL) {
		printf("Error opening save file.\n");
		return 1;
	}

	// Verify if the packet is from ethernet
	if(pcap_datalink(fp)!=DLT_EN10MB){
		printf("Given file is not from an ethernet source!!\n");
		return 1;
	}

	// Use pcap_loop to process all the packets continuously until EOF is reached
	pcap_loop(fp, -1, packet_header_extract, args);

	// Close pcap file
	pcap_close(fp);
	/*printf("wait\n");
	 int a;
	 scanf("%d",&a);*/

	end_time = clock();

	printf("\n========== Packet Capture Summary ==========\n");
	printf("Start Date and Time:\t%d-%d-%d %d:%d:%d %s\n", 1900
			+ loc_time->tm_year, 1 + loc_time->tm_mon, loc_time->tm_mday,
			loc_time->tm_hour, loc_time->tm_min, loc_time->tm_sec,
			loc_time->tm_zone);
	printf("Duration:\t\t %f\n", (double) (end_time - begin_time) / CLOCKS_PER_SEC);
	printf("Total Packets:\t\t %d\n", total_packets);
	printf("Minimum Packet Size:\t %d\n", min_packet_size);
	printf("Maximum Packet Size:\t %d\n", max_packet_size);
	printf("Average Packet Size:\t %d\n", sum_packet_sizes / total_packets);

	printf("\n========== Link Layer ==========\n");
	printf("\n---------- Source Ethernet Address and Count ----------\n");
	for (i = 0; ether_stat_source[i].count != 0; i++) {
		//printf("%s\t %d\n", ether_ntoa((const struct ether_addr *)ether_stat_source[i].ether_host),ether_stat_source[i].count);
		for (j = 0; j < ETH_ALEN; j++) {
			printf("%02x", ether_stat_source[i].ether_host[j]);
			if (j < ETH_ALEN - 1)
				printf(":");
		}
		printf("\t%d\n", ether_stat_source[i].count);

	}

	printf("\n---------- Destination Ethernet Address and Count ----------\n");
	for (i = 0; ether_stat_dest[i].count != 0; i++) {
		//printf("%s\t %d\n", ether_ntoa((const struct ether_addr *) ether_stat_dest[i].ether_host),ether_stat_dest[i].count);
		for (j = 0; j < ETH_ALEN; j++) {
			printf("%02x", ether_stat_dest[i].ether_host[j]);
			if (j < ETH_ALEN - 1)
				printf(":");
		}
		printf("\t%d\n", ether_stat_dest[i].count);
	}

	printf("\n========== Network Layer ==========\n");
	printf("\n---------- Network Layer Protocols ----------\n");
	for (i = 0; ether_type_list[i].count != 0; i++) {
		if (ntohs(ether_type_list[i].ether_type) == ETHERTYPE_IP || ntohs(
				ether_type_list[i].ether_type) == ETHERTYPE_ARP) {
			if (ntohs(ether_type_list[i].ether_type) == ETHERTYPE_IP)
				printf("IP\t\t %d\n", ether_type_list[i].count);
			if (ntohs(ether_type_list[i].ether_type) == ETHERTYPE_ARP)
				printf("ARP\t\t %d\n", ether_type_list[i].count);
		} else
			printf("%d (%#x)\t %d\n", ntohs(ether_type_list[i].ether_type),
					ether_type_list[i].ether_type, ether_type_list[i].count);
	}

	printf("\n---------- Source IP Address and Count ----------\n");
	for (i = 0; net_lyr_stat_source[i].count != 0; i++) {
		printf("%s\t %d\n", inet_ntoa(net_lyr_stat_source[i].ip_addr),
				net_lyr_stat_source[i].count);
	}

	printf("\n---------- Destination IP Address and Count ----------\n");
	for (i = 0; net_lyr_stat_dest[i].count != 0; i++) {
		printf("%s\t %d\n", inet_ntoa(net_lyr_stat_dest[i].ip_addr),
				net_lyr_stat_dest[i].count);
	}

	printf("\n---------- Unique ARP participants ----------\n");
	for (i = 0; arp_stat[i].count != 0; i++) {
		//printf("%s / %s \t %d\n", arp_stat[i].ha,arp_stat[i].ip,arp_stat[i].count);
		for (j = 0; j < ETH_ALEN; j++) {
			printf("%02x", arp_stat[i].ha[j]);
			if (j < ETH_ALEN - 1)
				printf(":");
		}
		printf(" / ");
		for (j = 0; j < 4; j++) {
			printf("%u", arp_stat[i].ip[j]);
			if (j < 4 - 1)
				printf(".");
		}
		printf("\t%d\n", arp_stat[i].count);
		//printf("%s / %s \t %d\n", ether_ntoa((const struct ether_addr *)arp_stat[i].ha),inet_ntoa(arp_stat[i].ip),arp_stat[i].count);
	}

	printf("\n========== Transport Layer ==========\n");
	printf("\n---------- Transport Layer Protocols ----------\n");
	for (i = 0; ipproto_type_list[i].count != 0; i++) {
		if (ipproto_type_list[i].ipproto_type == IPPROTO_TCP
				|| ipproto_type_list[i].ipproto_type == IPPROTO_UDP
				|| ipproto_type_list[i].ipproto_type == IPPROTO_ICMP
				|| ipproto_type_list[i].ipproto_type == 0) {
			if (ipproto_type_list[i].ipproto_type == IPPROTO_TCP)
				printf("TCP\t %d\n", ipproto_type_list[i].count);
			if (ipproto_type_list[i].ipproto_type == IPPROTO_UDP)
				printf("UDP\t %d\n", ipproto_type_list[i].count);
			if (ipproto_type_list[i].ipproto_type == IPPROTO_ICMP)
				printf("ICMP\t %d\n", ipproto_type_list[i].count);
			if (ipproto_type_list[i].ipproto_type == 0)
				continue;

		} else
			printf("%d\t %d\n", ipproto_type_list[i].ipproto_type,
					ipproto_type_list[i].count);
	}

	printf("\n---------- TCP Source Port and Count ----------\n");
	for (i = 0; tran_lyr_stat_tcp_source[i].count != 0; i++) {
		printf("%d\t %d\n", tran_lyr_stat_tcp_source[i].port,
				tran_lyr_stat_tcp_source[i].count);
	}

	printf("\n---------- TCP Destination Port and Count ----------\n");
	for (i = 0; tran_lyr_stat_tcp_dest[i].count != 0; i++) {
		//printf("destiantion port count");
		printf("%d\t %d\n", tran_lyr_stat_tcp_dest[i].port,
				tran_lyr_stat_tcp_dest[i].count);
	}

	printf("\n---------- TCP Flags ----------\n");

	for (i = 0; tcp_flag_stat_urg[i].count != 0; i++) {
		urg_cnt = 1;
		printf("URG\t %d\n", tcp_flag_stat_urg[i].count);
	}
	if (urg_cnt != 1)
		printf("URG\t %d\n", 0);

	for (i = 0; tcp_flag_stat_ack[i].count != 0; i++) {
		ack_cnt = 1;
		printf("ACK\t %d\n", tcp_flag_stat_ack[i].count);
	}
	if (ack_cnt != 1)
		printf("ACK\t %d\n", 0);

	for (i = 0; tcp_flag_stat_psh[i].count != 0; i++) {
		psh_cnt = 1;
		printf("PSH\t %d\n", tcp_flag_stat_psh[i].count);
	}
	if (psh_cnt != 1)
		printf("PSH\t %d\n", 0);

	for (i = 0; tcp_flag_stat_rst[i].count != 0; i++) {
		rst_cnt = 1;
		printf("RST\t %d\n", tcp_flag_stat_rst[i].count);
	}
	if (rst_cnt != 1)
		printf("RST\t %d\n", 0);

	for (i = 0; tcp_flag_stat_fin[i].count != 0; i++) {
		fin_cnt = 1;
		printf("FIN\t %d\n", tcp_flag_stat_fin[i].count);
	}
	if (fin_cnt != 1)
		printf("FIN\t %d\n", 0);

	for (i = 0; tcp_flag_stat_syn[i].count != 0; i++) {
		syn_cnt = 1;
		printf("SYN\t %d\n", tcp_flag_stat_syn[i].count);
	}
	if (syn_cnt != 1)
		printf("SYN\t %d\n", 0);

	printf("\n---------- TCP Options ----------\n");
	for (i = 0; tcp_opt_stat[i].count != 0; i++) {
		tcp_opt_cnt = 1;
		printf("%d (%#x)\t %d\n", tcp_opt_stat[i].kind, tcp_opt_stat[i].kind, tcp_opt_stat[i].count);
	}
	if (tcp_opt_cnt != 1)
			printf("(no results)\n");

	printf("\n---------- UDP Source Port and Count ----------\n");
	for (i = 0; tran_lyr_stat_udp_source[i].count != 0; i++) {
		printf("%d\t %d\n", tran_lyr_stat_udp_source[i].port,
				tran_lyr_stat_udp_source[i].count);
	}

	printf("\n---------- UDP Destination Port and Count ----------\n");
	for (i = 0; tran_lyr_stat_udp_dest[i].count != 0; i++) {
		printf("%d\t %d\n", tran_lyr_stat_udp_dest[i].port,
				tran_lyr_stat_udp_dest[i].count);
	}

	printf("\n---------- ICMP types ----------\n");
	for (i = 0; icmp_opt_type[i].count != 0; i++) {
		icmp_type_cnt = 1;
		printf("%d\t %d\n", icmp_opt_type[i].icmp_option,
				icmp_opt_type[i].count);
	}
	if (icmp_type_cnt != 1)
		printf("(no results)\n");

	printf("\n---------- ICMP codes ----------\n");
	for (i = 0; icmp_opt_type[i].count != 0; i++) {
		icmp_code_cnt = 1;
		printf("%d\t %d\n", icmp_opt_code[i].icmp_option,
				icmp_opt_code[i].count);
	}
	if (icmp_code_cnt != 1)
		printf("(no results)\n");

	return 0;
}

void initialize() {

	int i = 0;
	// Initialize all the counts to zero
	for (i = 0; i < MAX_ARR_SIZE; i++) {
		ether_stat_source[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		ether_stat_dest[i].count = 0;
	}

	for (i = 0; i < 10; i++) {
		ether_type_list[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		net_lyr_stat_source[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		net_lyr_stat_dest[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		arp_stat[i].count = 0;
	}

	for (i = 0; i < 10; i++) {
		ipproto_type_list[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		tran_lyr_stat_tcp_source[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		tran_lyr_stat_tcp_dest[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		tcp_flag_stat_ack[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		tcp_flag_stat_syn[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		tcp_flag_stat_rst[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		tcp_flag_stat_fin[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		tcp_flag_stat_psh[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		tcp_flag_stat_urg[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		tran_lyr_stat_udp_source[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		tran_lyr_stat_udp_dest[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		icmp_opt_type[i].count = 0;
	}

	for (i = 0; i < MAX_ARR_SIZE; i++) {
		icmp_opt_code[i].count = 0;
	}

	for (i = 0; i < UCHAR_MAX + 1; i++) {
		tcp_opt_stat[i].count = 0;
	}

}

// Packet Handler that extracts headers for multiple layers - Data link, network and transport layers
void packet_header_extract(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	total_packets++;
	//printf("packet nbr: %d\n",total_packets);
	int i=0;
	sum_packet_sizes += pkthdr->len;
	min_packet_size = min_packet_size < pkthdr->len ? min_packet_size : pkthdr->len;
	max_packet_size = max_packet_size > pkthdr->len ? max_packet_size : pkthdr->len;

	u_int8_t tran_lyr_type = 0;

	// extract data link layer header
	u_int16_t type = handle_ethernet(args, pkthdr, packet);

	// Handle IP Layer header
	if (ntohs(type) == ETHERTYPE_IP) {
		tran_lyr_type = handle_IP(args, pkthdr, packet);
	} else if (ntohs(type) == ETHERTYPE_ARP) {
		handle_ARP(args, pkthdr, packet);
	}

	// extract transport layer header
	if (tran_lyr_type == IPPROTO_TCP) {
		/* handle TCP packet */
		handle_TCP(args, pkthdr, packet);
	}

	if (tran_lyr_type == IPPROTO_UDP) {
		/* handle TCP packet */
		handle_UDP(args, pkthdr, packet);
	} /* ignore */

	if (tran_lyr_type == IPPROTO_ICMP) {
		/* handle TCP packet */
		handle_ICMP(args, pkthdr, packet);
	} /* ignore */

	/*count for each transport layer protocols*/

	for (i = 0; ipproto_type_list[i].count != 0; i++) {
		if (!memcmp(&ipproto_type_list[i].ipproto_type, &tran_lyr_type,
				sizeof(tran_lyr_type)))
			break;
	}
	if (ipproto_type_list[i].count == 0)
		ipproto_type_list[i].ipproto_type = tran_lyr_type;

	ipproto_type_list[i].count++;

}

u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	int i = 0;
	struct ether_header *eptr; // net/ethernet.h

	eptr = (struct ether_header *) packet;

	// first search if ethernet address is already present in the list
	for (i = 0; ether_stat_source[i].count != 0; i++) {
		if (!memcmp(&ether_stat_source[i].ether_host, &eptr->ether_shost, ETH_ALEN))
			break;
	}
	// if it is not found add it the list
	if (ether_stat_source[i].count == 0)
		memcpy(&ether_stat_source[i].ether_host, &eptr->ether_shost, ETH_ALEN);

	// increment count for every case
	ether_stat_source[i].count++;

	// first search if ethernet address is already present in the list
	for (i = 0; ether_stat_dest[i].count != 0; i++) {
		if (!memcmp(&ether_stat_dest[i].ether_host, &eptr->ether_dhost,
				ETH_ALEN))
			break;
	}
	// if it is not found add it the list
	if (ether_stat_dest[i].count == 0)
		memcpy(&ether_stat_dest[i].ether_host, &eptr->ether_dhost, ETH_ALEN);

	// increment count for every case
	ether_stat_dest[i].count++;

	// Below code will maintain stats about of IP layer protocols
	// first search if IP protocol type is already present in the list
	for (i = 0; ether_type_list[i].count != 0; i++) {
		if (!memcmp(&ether_type_list[i].ether_type, &eptr->ether_type,
				sizeof(eptr->ether_type)))
			break;
	}
	// if it is not found add it the list
	if (ether_type_list[i].count == 0)
		ether_type_list[i].ether_type = eptr->ether_type;

	// increment count for every case
	ether_type_list[i].count++;

	//printf("Ethernet header:    source: %s    ", ether_ntoa((const struct ether_addr *)eptr->ether_shost));
	//printf("destination: %s ", ether_ntoa((const struct ether_addr *)eptr->ether_dhost));

	return eptr->ether_type;
}

u_int8_t handle_IP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct my_ip* ip;
	u_int length = pkthdr->len;
	u_int hlen, off, version;
	int i = 0;
	u_int len;
	// point to IP header
	ip = (struct my_ip*) (packet + sizeof(struct ether_header));
	length -= sizeof(struct ether_header);
	// verify the length
	if (length < sizeof(struct my_ip)) {
		printf("truncated ip %d", length);
		return NULL;
	}
	len = ntohs(ip->ip_len);
	hlen = IP_HL(ip); // header length
	version = IP_V(ip); // ip version
	/* check version */
	if (version != 4) {
		fprintf(stdout, "Unknown version %d\n", version);
		return NULL;
	}
	/* check header length */
	if (hlen < 5) {
		fprintf(stdout, "bad-hlen %d \n", hlen);
	}
	/* see if we have as much packet as we should */
	if (length < len)
		printf("\ntruncated IP - %d bytes missing\n", len - length);
	/* Check to see if we have the first fragment */
	off = ntohs(ip->ip_off);
	if ((off & 0x1fff) == 0) /* aka no 1's in first 13 bits */
	{
		for (i = 0; net_lyr_stat_source[i].count != 0; i++) {
			if (!memcmp(&net_lyr_stat_source[i].ip_addr, &ip->ip_src,
					sizeof(ip->ip_src)))
				break;
		}
		if (net_lyr_stat_source[i].count == 0)
			memcpy(&net_lyr_stat_source[i].ip_addr, &ip->ip_src,
					sizeof(ip->ip_src));

		net_lyr_stat_source[i].count++;

		for (i = 0; net_lyr_stat_dest[i].count != 0; i++) {
			if (!memcmp(&net_lyr_stat_dest[i].ip_addr, &ip->ip_dst,
					sizeof(ip->ip_dst)))
				break;
		}
		if (net_lyr_stat_dest[i].count == 0)
			memcpy(&net_lyr_stat_dest[i].ip_addr, &ip->ip_dst,
					sizeof(ip->ip_dst));

		net_lyr_stat_dest[i].count++;

		/* print SOURCE DESTINATION hlen version len offset */
		//fprintf(stdout, "IP: ");
		//fprintf(stdout, "source: %s ", inet_ntoa(ip->ip_src));
		//fprintf(stdout, "destination: %s %d %d %d %d\n", inet_ntoa(ip->ip_dst), hlen, version, len, off);
	}
	return ip->ip_p;
}

u_char* handle_ARP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct my_arphdr* arp;
	u_int length = pkthdr->len;

	int i = 0;

	// point to arp header
	arp = (struct my_arphdr*) (packet + sizeof(struct ether_header));
	length -= sizeof(struct ether_header);
	// verify the length
	if (length < sizeof(struct my_arphdr)) {
		printf("truncated arp %d", length);
		return NULL;
	}

	// For Ethernet and IPv4 print stats
	if (ntohs(arp->ar_hrd) == ARPHRD_ETHER && ntohs(arp->ar_pro)
			== ETHERTYPE_IP) {
		for (i = 0; arp_stat[i].count != 0; i++) {
			//printf("src mac: %s src ip: %s dest mac: %s dest ip: %s\n",arp->__ar_sha,arp->__ar_sip,arp->__ar_tha,arp->__ar_tip);
			if (!memcmp(&arp_stat[i], &arp->__ar_sha, sizeof(arp->__ar_sha)
					+ sizeof(arp->__ar_sip)))
				break;
		}
		if (arp_stat[i].count == 0) {
			memcpy(&arp_stat[i].ha, &arp->__ar_sha, sizeof(arp->__ar_sha));
			memcpy(&arp_stat[i].ip, &arp->__ar_sip, sizeof(arp->__ar_sip));
		}

		arp_stat[i].count++;
	}

	return NULL;
}

u_char* handle_TCP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct tcphdr* tcp;
	u_int length = pkthdr->len;

	/*u_int16_t res1:4;
	 u_int16_t doff:4;
	 u_int16_t fin:1;
	 u_int16_t syn:1;
	 u_int16_t rst:1;
	 u_int16_t psh:1;
	 u_int16_t ack:1;
	 u_int16_t urg:1;
	 u_int16_t res2:2;*/

	u_int16_t sport, dport, doff, fin, syn, rst, psh, ack, urg, res1, res2;
	u_int16_t window, check, urg_ptr;
	u_int32_t seq, ack_seq;
	int i = 0;
	char *temp;
	char kind = 0, lgth = 0;
	int length_parsed = 20;
	//int kind_i = 0, lgth_i = 0;
	//kind_i = atoi(&kind);
	//lgth_i = atoi(&kind);

	/* jump pass the ethernet header */
	tcp = (struct tcphdr*) (packet + sizeof(struct ether_header)
			+ sizeof(struct my_ip));
	length -= sizeof(struct ether_header);
	length -= sizeof(struct my_ip);

	/* check to see we have a packet of valid length */
	if (length < sizeof(struct tcphdr)) {
		printf("truncated tcp %d", length);
		return NULL;
	}

	sport = (u_int16_t) ntohs(tcp->source);
	dport = (u_int16_t) ntohs(tcp->dest);
	seq = (u_int32_t) ntohs(tcp->seq);
	ack_seq = (u_int32_t) ntohs(tcp->ack_seq);
	doff = (u_int16_t) tcp->doff;
	//printf("doff: %d\n",doff);
	fin = (u_int16_t) ntohs(tcp->fin);
	rst = (u_int16_t) ntohs(tcp->rst);
	psh = (u_int16_t) ntohs(tcp->psh);
	ack = (u_int16_t) ntohs(tcp->ack);
	urg = (u_int16_t) ntohs(tcp->urg);
	syn = (u_int16_t) ntohs(tcp->syn);
	res1 = (u_int16_t) ntohs(tcp->res1);
	res2 = (u_int16_t) ntohs(tcp->res2);
	window = (u_int16_t) ntohs(tcp->window);
	check = (u_int16_t) ntohs(tcp->check);
	urg_ptr = (u_int16_t) ntohs(tcp->urg_ptr);

	if (total_packets == 221)
		total_packets = total_packets;

	temp = (char *) tcp + 20;
	//printf("%s",temp);

	do {
		temp += lgth;
		length_parsed += lgth;
		if (kind != 0) {

			for (i = 0; tcp_opt_stat[i].count != 0; i++) {
				if (!memcmp(&tcp_opt_stat[i].kind, &kind, sizeof(kind)))
					break;
			}
			if (tcp_opt_stat[i].count == 0)
				memcpy(&tcp_opt_stat[i].kind, &kind, sizeof(kind));

			tcp_opt_stat[i].count++;

		}

		strncpy(&kind, temp, sizeof(char));
		if (kind != 1)
			strncpy(&lgth, temp + 1, sizeof(char));
		else
			lgth = 1;
	} while (kind != 0 && length_parsed < doff * 4);

	for (i = 0; tran_lyr_stat_tcp_source[i].count != 0; i++) {
		if (!memcmp(&tran_lyr_stat_tcp_source[i].port, &sport, sizeof(sport)))
			break;
	}
	if (tran_lyr_stat_tcp_source[i].count == 0)
		memcpy(&tran_lyr_stat_tcp_source[i].port, &sport, sizeof(sport));

	tran_lyr_stat_tcp_source[i].count++;

	for (i = 0; tran_lyr_stat_tcp_dest[i].count != 0; i++) {
		if (!memcmp(&tran_lyr_stat_tcp_dest[i].port, &dport, sizeof(dport)))
			break;
	}
	if (tran_lyr_stat_tcp_dest[i].count == 0)
		memcpy(&tran_lyr_stat_tcp_dest[i].port, &dport, sizeof(dport));

	tran_lyr_stat_tcp_dest[i].count++;

	/* print TCP flags*/

	for (i = 0; tcp_flag_stat_urg[i].count != 0; i++) {
		if (!memcmp(&tcp_flag_stat_urg[i].flag, &urg, sizeof(urg)))
			break;
	}
	if (tcp_flag_stat_urg[i].count == 0)
		memcpy(&tcp_flag_stat_urg[i].flag, &urg, sizeof(urg));

	if (urg != 0)
		tcp_flag_stat_urg[i].count++;

	for (i = 0; tcp_flag_stat_ack[i].count != 0; i++) {
		if (!memcmp(&tcp_flag_stat_ack[i].flag, &ack, sizeof(ack)))
			break;
	}
	if (tcp_flag_stat_ack[i].count == 0)
		memcpy(&tcp_flag_stat_ack[i].flag, &ack, sizeof(ack));

	if (ack != 0)
		tcp_flag_stat_ack[i].count++;

	for (i = 0; tcp_flag_stat_psh[i].count != 0; i++) {
		if (!memcmp(&tcp_flag_stat_psh[i].flag, &psh, sizeof(psh)))
			break;
	}
	if (tcp_flag_stat_psh[i].count == 0)
		memcpy(&tcp_flag_stat_psh[i].flag, &psh, sizeof(psh));

	if (psh != 0)
		tcp_flag_stat_psh[i].count++;

	for (i = 0; tcp_flag_stat_rst[i].count != 0; i++) {
		if (!memcmp(&tcp_flag_stat_rst[i].flag, &rst, sizeof(rst)))
			break;
	}
	if (tcp_flag_stat_rst[i].count == 0)
		memcpy(&tcp_flag_stat_rst[i].flag, &rst, sizeof(rst));

	if (rst != 0)
		tcp_flag_stat_rst[i].count++;

	for (i = 0; tcp_flag_stat_fin[i].count != 0; i++) {
		if (!memcmp(&tcp_flag_stat_fin[i].flag, &fin, sizeof(fin)))
			break;
	}
	if (tcp_flag_stat_fin[i].count == 0)
		memcpy(&tcp_flag_stat_fin[i].flag, &fin, sizeof(fin));

	if (fin != 0)
		tcp_flag_stat_fin[i].count++;

	for (i = 0; tcp_flag_stat_syn[i].count != 0; i++) {
		if (!memcmp(&tcp_flag_stat_syn[i].flag, &syn, sizeof(syn)))
			break;
	}
	if (tcp_flag_stat_syn[i].count == 0)
		memcpy(&tcp_flag_stat_syn[i].flag, &syn, sizeof(syn));

	if (syn != 0)
		tcp_flag_stat_syn[i].count++;

	/* print SOURCE and DESTINATION ports
	 fprintf(stdout, "TCP:\n ");
	 fprintf(stdout,"\n");
	 fprintf(stdout, "TCP_sport: %d\n", sport);
	 fprintf(stdout, "TCP_dport: %d\n", dport);
	 fprintf(stdout, "sequence number: %d\n", seq);
	 fprintf(stdout, "ack.sequence num: %d\n", ack_seq);
	 fprintf(stdout, "FIN: %d\n", fin);
	 fprintf(stdout, "RST: %d\n", rst);
	 fprintf(stdout, "PSH: %d\n", psh);
	 fprintf(stdout, "ACK: %d\n", ack);
	 fprintf(stdout, "URG: %d\n", urg);
	 fprintf(stdout, "RES1: %d\n", res1);
	 fprintf(stdout, "RES2: %d\n", res2);
	 fprintf(stdout, "Window: %d\n", window);
	 fprintf(stdout, "CHECK: %d\n", check);
	 fprintf(stdout, "URG_PTR: %d\n", urg_ptr);
	 print TCP options */

	return NULL;
}

u_char* handle_UDP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct udphdr* udp;
	u_int length = pkthdr->len;
	u_int16_t sport, dport;
	int i = 0;

	/* jump pass the ethernet header */
	udp = (struct udphdr*) (packet + sizeof(struct ether_header)
			+ sizeof(struct my_ip));
	length -= sizeof(struct ether_header);
	length -= sizeof(struct my_ip);
	/* check to see we have a packet of valid length */
	if (length < sizeof(struct udphdr)) {
		printf("truncated udp %d", length);
		return NULL;
	}

	sport = (u_int16_t) ntohs(udp->source);
	dport = (u_int16_t) ntohs(udp->dest);

	/*count source and destination ports*/

	for (i = 0; tran_lyr_stat_udp_source[i].count != 0; i++) {
		if (!memcmp(&tran_lyr_stat_udp_source[i].port, &sport, sizeof(sport)))
			break;
	}
	if (tran_lyr_stat_udp_source[i].count == 0)
		memcpy(&tran_lyr_stat_udp_source[i].port, &sport, sizeof(sport));

	tran_lyr_stat_udp_source[i].count++;

	for (i = 0; tran_lyr_stat_udp_dest[i].count != 0; i++) {
		if (!memcmp(&tran_lyr_stat_udp_dest[i].port, &dport, sizeof(dport)))
			break;
	}
	if (tran_lyr_stat_udp_dest[i].count == 0)
		memcpy(&tran_lyr_stat_udp_dest[i].port, &dport, sizeof(dport));

	tran_lyr_stat_udp_dest[i].count++;

	//ulen = (u_int16_t) ntohs(udp->len);
	//checksum = (u_int16_t) ntohs(udp->check);

	/* print SOURCE and DESTINATION ports
	 fprintf(stdout, "UDP:\n ");
	 fprintf(stdout, "UDP_sport: %d\n ", sport);
	 fprintf(stdout, "UDP_dport: %d\n", dport);
	 fprintf(stdout, "UDP_Length: %d\n", ulen);
	 fprintf(stdout, "UDP_Cheksum: %d\n", checksum);*/

	return NULL;
}

u_char* handle_ICMP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct icmphdr* icmp;
	u_int length = pkthdr->len;
	u_int8_t type, code; /* message type, type sub-code */
	int i = 0;
	//u_int16_t id,sequence,checksum,unused,mtu;
	//u_int32_t gateway;

	/* jump pass the ethernet header */
	icmp = (struct icmphdr*) (packet + sizeof(struct ether_header)
			+ sizeof(struct my_ip));
	length -= sizeof(struct ether_header);
	length -= sizeof(struct my_ip);
	/* check to see we have a packet of valid length */
	if (length < sizeof(struct icmphdr)) {
		printf("truncated udp %d", length);
		return NULL;
	}

	type = icmp->type;
	code = icmp->code;

	/*count ICMP types and codes*/

	for (i = 0; icmp_opt_type[i].count != 0; i++) {
		if (!memcmp(&icmp_opt_type[i].icmp_option, &type, sizeof(type)))
			break;
	}
	if (icmp_opt_type[i].count == 0)
		memcpy(&icmp_opt_type[i].icmp_option, &type, sizeof(type));

	icmp_opt_type[i].count++;

	for (i = 0; icmp_opt_code[i].count != 0; i++) {
		if (!memcmp(&icmp_opt_code[i].icmp_option, &code, sizeof(code)))
			break;
	}
	if (icmp_opt_code[i].count == 0)
		memcpy(&icmp_opt_code[i].icmp_option, &code, sizeof(code));

	icmp_opt_code[i].count++;

	/*id = (u_int16_t) ntohs(icmp->id);
	 checksum = (u_int16_t) ntohs(icmp->checksum);
	 sequence = (u_int16_t) ntohs(icmp->sequence);
	 unused = (u_int16_t) ntohs(icmp->_unused);
	 mtu = (u_int16_t) ntohs(icmp->mtu);
	 gateway = (u_int32_t) ntohs(icmp->gateway);

	 print SOURCE and DESTINATION ports
	 fprintf(stdout, "ICMP:\n ");
	 fprintf(stdout, "ICMP:type: %d\n ", type);
	 fprintf(stdout, "ICMP_code: %d\n", code);*/

	return NULL;
}
