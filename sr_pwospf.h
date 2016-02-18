/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>
#include <stdint.h>
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_if.h"

#ifdef VNL
#include "vnlconn.h"
#endif

/* forward declare */
struct sr_instance;

struct pwospf_subsys
{
    /* -- pwospf subsystem state variables here -- */


    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
};

int pwospf_init(struct sr_instance* sr);
void pwospf_lock(struct pwospf_subsys* subsys);
void pwosf_unlock(struct pwospf_subsys* subsys);
static void* pwospf_run_thread(void* arg);
void periodic_refresh(struct sr_instance* sr);
void* send_hello(void* arg);
void* send_hello_pkt(void* arg);
void* linkStateUpdate(void* arg);
void* lsflooding(void* arg);
void handle_hello_pkts(struct sr_instance*,uint8_t*,unsigned int, char* interface,struct sr_if*);
void* linkup(void* arg);
uint8_t check_route(struct sr_instance* sr, uint32_t route);
void* refresh_topo(void* arg);
void search_routes(struct sr_instance* sr,uint32_t sender_ip, struct timeval time, struct timeval past,int n);
int search_database(struct sr_instance* sr,struct in_addr sender_rid,uint8_t* packet, uint16_t seqno);
void add_routes(struct sr_instance* sr,uint8_t* outPkt,uint32_t sender_ip, struct timeval time);
void add_database(struct sr_instance* sr,struct in_addr sender_rid,uint8_t* packet,struct in_addr sender_ip, uint16_t seqno,uint8_t* outPkt);
int search_topo(struct sr_instance* sr,struct lsa_packet* packet);
void my_algo(struct sr_instance* sr);


/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_handlepacket(struct sr_instance* sr, uint8_t * packet, unsigned int len,char* interface);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance*,const char*);
void sr_set_ether_ip(struct sr_instance*,uint32_t);
void sr_set_ether_addr(struct sr_instance*,const unsigned char*);
void sr_print_if_list(struct sr_instance*);


#endif /* SR_PWOSPF_H */
