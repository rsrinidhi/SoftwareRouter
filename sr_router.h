/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 * 90904102
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_if.h"
#include "sr_pwospf.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

#define ICMP_DEST_UNREACHABLE 3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_TRACEROUTE 30

#define PORT_UNREACHABLE 3
#define HOST_UNREACHABLE 1
#define ICMP_SOURCEROUTE_FAILED 5
#define DESTINATION_HOST_UNREACHABLE 7
#define NET_UNREACHABLE 0
#define PROTOCOL_UNREACHABLE 2

#define TTL 0

#ifndef UDP
#define UDP    0x0001
#endif

#ifndef TCP
#define TCP    0x0006
#endif

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_packet_cache {
    uint32_t dst_ip;
    uint8_t content[1514];
    int len;
    int queue;
    struct sr_packet_cache *next;
};

struct sr_arp_cache {
    uint32_t ip;
    unsigned char addr[6];
    struct timeval time;
    struct sr_arp_cache* next;
};

struct sr_icmp_hdr
{
    unsigned char   icmp_type;
    unsigned char   icmp_code;
    uint16_t icmp_id;
    uint16_t icmp_seq;
    unsigned short  icmp_chksum;
} __attribute__ ((packed)) ;

#ifndef ICMP_ECHO_REQUEST
#define ICMP_ECHO_REQUEST           8  
#endif

#ifndef ICMP_ECHO_REPLY
#define ICMP_ECHO_REPLY             0
#endif



struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    FILE* logfile;
    volatile uint8_t  hw_init; /* bool : hardware has been initialized */
    
    /*---Added--------*/
    uint8_t num_adv;	
    uint32_t rid;
    uint32_t aid;
   // uint16_t lsuint;
    struct timeval lsuint;
    uint16_t seqno;
    uint16_t autype;
    char interface[SR_IFACE_NAMELEN];
    struct database* Database;
    struct lsa_packet* adv;
    struct my_rt* my_routing_table;

     /* -- pwospf subsystem -- */
    struct pwospf_subsys* ospf_subsys;
};

struct sr_icmp
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t* packet;
    uint16_t ID;
    uint16_t seq_no;
};


/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance*);
void sr_handlepacket(struct sr_instance* sr, uint8_t * packet, unsigned int len,char* interface);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance*,const char*);
void sr_set_ether_ip(struct sr_instance*,uint32_t);
void sr_set_ether_addr(struct sr_instance*,const unsigned char*);
void sr_print_if_list(struct sr_instance*);


/*-- sr_pwospf.c--*/
//void handle_pwosf_packet(struct sr_instance* sr,uint8_t * packet,unsigned int len,char* interface);
#endif /* SR_ROUTER_H */

