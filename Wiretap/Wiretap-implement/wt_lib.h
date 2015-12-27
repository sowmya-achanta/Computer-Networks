/*
 * wt_lib.h
 *
 *  Created on: Oct 27, 2014
 *      Author: jmadagun
 */

#ifndef WT_LIB_H_
#define WT_LIB_H_

struct my_ip {
	u_int8_t ip_vhl; /* header length, version */
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
	u_int8_t ip_tos; /* type of service */
	u_int16_t ip_len; /* total length */
	u_int16_t ip_id; /* identification */
	u_int16_t ip_off; /* fragment offset field */
#define IP_DF 0x4000 /* don't fragment flag */
#define IP_MF 0x2000 /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
	u_int8_t ip_ttl; /* time to live */
	u_int8_t ip_p; /* protocol */
	u_int16_t ip_sum; /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct my_arphdr
{
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
    unsigned char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char __ar_sip[4];		/* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char __ar_tip[4];		/* Target IP address.  */
};

typedef struct ethernet_statistics {
	u_int8_t  ether_host[ETH_ALEN];
	u_int count;
} ether_stat_t;

typedef struct ethernet_types {
	u_int16_t ether_type;
	u_int count;
} ether_type_list_t;

typedef struct network_layer_statistics {
	struct in_addr ip_addr;
	u_int count;
} net_lyr_stat_t;

typedef struct arp_statistics {
    unsigned char ha[ETH_ALEN];
    unsigned char ip[4];
    u_int count;
} arp_stat_t;

typedef struct ipproto_types {
	u_int8_t ipproto_type;
	u_int count;
} ipproto_type_list_t;

typedef struct transport_layer_statistics {
	u_int16_t port;
	u_int count;
} tran_lyr_stat_t;

typedef struct tcp_flags_statistics{
	u_int16_t flag;
	u_int count;
} tcp_flag_stat_t;

typedef struct tcp_options {
	unsigned char kind;
	u_int count;
} tcp_opt_t;

typedef struct icmp_options {
	u_int8_t icmp_option;
	u_int count;
} icmp_opt_t;


#define MAX_ARR_SIZE 1024

#endif /* WT_LIB_H_ */
