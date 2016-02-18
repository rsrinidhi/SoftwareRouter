
/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_if.h"
#include "sr_rt.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>

/*Initialise threads here*/
pthread_t* hello_pkt;
pthread_t* hello;
pthread_t* refresh_neighbor;
pthread_t* lsupdate;
pthread_t* lsflood;
pthread_t* linkupdate;
pthread_t* refresh_topology;

/*Initialise variables here*/
uint8_t ospf_daddr[ETHER_ADDR_LEN];
uint16_t seq;
int up;
int counter;
int lsu_status=0;
uint8_t lsu_ttl;
int hello_timer=0;
int lsu_timer=0;
int neighbor_timer=0;



int db_init=0;
/*Initialise structures here*/
struct in_addr router_addr;
struct in_addr default_addr;
struct sr_if* lsu_if;

struct dijkstra_item* dijkstra_stack;
struct dijkstra_item* dijkstra_heap;

/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);
/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    
    printf("Initializing the OSPF subsystem\n");
    assert(sr);
    
    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct pwospf_subsys));
    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);
    
    
    /* -- handle subsystem initialization here! -- */
    
    //Default rid of router 0 is 0
    default_addr.s_addr=0;
    struct sr_if* iface = sr->if_list;
    
    while(iface!=NULL)
    {
        printf("Creating default neighbors\n");
        iface->neighbour_ip=0;
        iface->neighbour_rid=0;
        iface->neighbour_helloint.tv_sec=0;
        iface= iface->next;
    }
    
    router_addr.s_addr=0;
    seq=0;
    up=0;
    counter=0;
    
    //sr->lsuint=OSPF_DEFAULT_LSUINT;
    sr->aid=0;
    sr->rid=0;	
    sr->autype=0;
    sr->num_adv=0;
    sr->Database=0;
    sr->adv=0;
    sr->my_routing_table=0;
    sr->seqno=0;
    hello_timer=0;
 

    lsu_ttl=OSPF_MAX_LSU_TTL;
    
    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
        perror("pthread_create");
        assert(0);
    }
    
    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    printf("My host ID %s\n", sr->host);
    
    pthread_create(&hello,NULL, send_hello, sr);
    pthread_create(&lsflood,NULL,lsflooding,sr);
    
    return NULL;
} /* -- run_ospf_thread -- */

/*---------------------------------------------------------------------
 * Method: void periodic_refresh()
 * check the neighbor's timer interval
 * If it has not been updated, then it should be removed
 *
 *---------------------------------------------------------------------*/

void periodic_refresh(struct sr_instance* sr)
{
    struct sr_if* iface= sr->if_list;

    struct lsa_packet* lsa_record =0;
    struct lsa_packet* new_record=0;
    struct database* new_db_record=0;
    struct database* db_record=0;
    
    lsa_record = sr->adv;
    db_record = sr->Database;

    struct timeval MAX_TIME;
    struct timeval current;
    struct timeval result;

    MAX_TIME.tv_sec = OSPF_NEIGHBOR_TIMEOUT;

      
	if(sr->Database == 0 || sr->adv==0 || lsa_record==0 || db_record==0)
        {
           return;
        }

	
	while(iface!=NULL)
        {
            if(iface->ip > router_addr.s_addr)
            {
                    router_addr.s_addr = iface->ip;
                    sr->rid= iface->ip;
            }
            iface=iface->next;
        }
        
        iface = sr->if_list;

	
        while(iface!=NULL)
        {
            if(iface->neighbour_ip!=0)
            {
                if(neighbor_timer==1)
		{

		    gettimeofday(&current, NULL);
                    timersub(&current, &(iface->neighbour_helloint), &result);
                   
		    if (result.tv_sec >= MAX_TIME.tv_sec)
		    {
				pwospf_lock(sr->ospf_subsys);
			        while(lsa_record->next!=0)
        			{
				        new_record = lsa_record->next;
		    	            	 if(new_record->ip == iface->neighbour_ip)
		    			 {
		        			printf("Removing topology in refresh\n");
		                    		lsa_record->next = new_record->next;
		        			free(new_record);	
			    		 }
					 
					else 
					{
						lsa_record = lsa_record->next;
					}
        			}
        
        
				lsa_record = sr->adv;
				if(lsa_record->ip == iface->neighbour_ip)
				{
				  
				    lsa_record=sr->adv->next;
				    free(sr->adv);
				    sr->adv = lsa_record;
				    printf("First element has been removed in refresh\n");
				}

				db_record=sr->Database;

				while(db_record->next!=0)
				{
				    new_db_record = db_record->next;
		    
				    if (new_db_record->sender_ip.s_addr == iface->neighbour_ip)
				    {
					
					printf("Removing Database in refresh\n");
					db_record->next = new_db_record->next;
					free(new_db_record);		
				    }
				    else 
				    {
 
					db_record = db_record->next;
				    }
				}
		
		
	       		       db_record = sr->Database;

			       if (db_record->sender_ip.s_addr == iface->neighbour_ip)
				{
				    db_record=sr->Database->next;
				    free(sr->Database);
				    sr->Database = db_record;
				    printf("First record in database has been removed\n");
				}
			   	

			       iface->neighbour_ip=0;
		               iface->neighbour_rid=0;
			       my_algo(sr);
			
		     	       struct ospfv2_lsu_update* lsu_update=((struct ospfv2_lsu_update*)malloc(sizeof(struct ospfv2_lsu_update)));
		               lsu_update->sr=sr;
		               lsu_update->iface=iface;
		               lsu_update->rid=sr->rid;
		   
		               printf("Link State Update\n");
		               pthread_create(&linkupdate, NULL, linkup, lsu_update);
			       gettimeofday(&(sr->lsuint), NULL);
			       pwospf_unlock(sr->ospf_subsys);
                   }
	     	}
             }
            
            iface=iface->next;
        }
	
 }
/*---------------------------------------------------------------------
 * Method: void send_hello()
 *
 * Thread for checking if the hello interval is expired
 * If yes, send the hello packet
 * If not, decrement the time interval
 *---------------------------------------------------------------------*/

void* send_hello(void* arg)
{
    struct sr_instance* sr=(struct sr_instance*)arg;
    struct timeval MAX_TIME;
    struct timeval current;
    struct timeval result;

    MAX_TIME.tv_sec = OSPF_DEFAULT_HELLOINT;
	
	while(1){
	usleep(1000* OSPF_DEFAULT_HELLOINT);
	

    
        struct sr_if* iface = sr->if_list;
        
        if(iface==NULL)
            return;
        
        while(iface!=NULL)
        {
            if(iface->ip > router_addr.s_addr)
            {
		    router_addr.s_addr = iface->ip;
		    sr->rid= iface->ip;
            }
            iface=iface->next;
        }
        
        iface = sr->if_list;
        
        while(iface!=NULL)
        {
            struct in_addr temp;
            temp.s_addr= iface->mask;
            temp.s_addr= iface->ip;
            
            iface= iface->next;
            
        }
        
        iface = sr->if_list;
	
	pwospf_lock(sr->ospf_subsys);
        while(iface!= NULL)
        {
            if(hello_timer==0)
            {
                //Hello interval not yet expired

		printf("HELLOINT Timeout!!!\n");
                struct ospfv2_hello_packet* hello_packet = ((struct ospfv2_hello_packet*)malloc(sizeof(struct ospfv2_hello_packet)));
                hello_packet->iface= iface;
                hello_packet->sr=sr;
                memcpy(hello_packet->daddr,iface->addr,ETHER_ADDR_LEN);
                pthread_create(&hello_pkt, NULL, send_hello_pkt,hello_packet);
		gettimeofday(&iface->helloint, NULL);
		
		hello_timer=1;
            }
            
            else if(hello_timer ==1)
            {
                //Hello interval has expired
                //Send Hello packet to the interface
                //hello_pkt is created to encapsulate the interface and the sr_instance
                
		gettimeofday(&current, NULL);
		timersub(&current, &(iface->helloint), &result);


		if (result.tv_sec >= MAX_TIME.tv_sec)
		{
           	     printf("HELLOINT Timeout!!!\n");
                     struct ospfv2_hello_packet* hello_packet = ((struct ospfv2_hello_packet*)malloc(sizeof(struct ospfv2_hello_packet)));
                     hello_packet->iface= iface;
                     hello_packet->sr=sr;
                     memcpy(hello_packet->daddr,iface->addr,ETHER_ADDR_LEN);
		     
		     pthread_create(&hello_pkt, NULL, send_hello_pkt,hello_packet);
		     gettimeofday(&iface->helloint, NULL);
		}            
	   }
            
            iface= iface->next;
        }
	pwospf_unlock(sr->ospf_subsys);
	periodic_refresh(sr);        

	};
    return NULL;
}

/*--------------------------------------------------------------------------------------------------------------
 * Method:void* linkStateFlooding(void* arg)
 * Scope:  Global
 *
 *-------------------------------------------------------------------------------------------------------------*/
void* lsflooding(void* arg)
{
    
    struct sr_instance* sr= ((struct sr_instance*)arg);
    struct sr_if* iface= sr->if_list;
    struct timeval MAX_TIME;
    struct timeval current;
    struct timeval result;

    MAX_TIME.tv_sec = OSPF_DEFAULT_LSUINT;

    printf("Entering the LSU function \n");
    
	while(1){
	usleep(100000 * OSPF_DEFAULT_LSUINT);
	pwospf_lock(sr->ospf_subsys);
        struct sr_if* iface = sr->if_list;
        if(iface==NULL)
            return;
        
        while(iface!=NULL)
        {
            if(iface->ip > router_addr.s_addr)
            {
		router_addr.s_addr = iface->ip;
            	sr->rid=iface->ip;
	    }

            iface=iface->next;
        }
	
	if(lsu_status==1)
	{
	  gettimeofday(&(sr->lsuint), NULL);	
	}
	
        if(lsu_timer ==0)
	{
	   pthread_create(&lsupdate,NULL,linkStateUpdate,sr);
       	   gettimeofday(&(sr->lsuint), NULL);
	   lsu_timer=1;
                
	}

        else if(lsu_timer==1 || lsu_status==0)
        {
            
	    gettimeofday(&current, NULL);
            timersub(&current, &(sr->lsuint), &result);

            //LSU interval has expired
            //Send LSU packet to the neighboring routers
		            
	    if (result.tv_sec >= MAX_TIME.tv_sec)
            {
		printf("LSU Timer has expired\n");	
            	pthread_create(&lsupdate,NULL,linkStateUpdate,sr);
            	gettimeofday(&(sr->lsuint), NULL);
            }
        }
    		pwospf_unlock(sr->ospf_subsys);
	};    
    return NULL;
}


/*---------------------------------------------------------------------
 * Method: void* send_hello_pkt(void* arg)
 * * Sending hello packets
 *---------------------------------------------------------------------*/

void* send_hello_pkt(void* arg)
{
    printf(" Constructing the hello packet \n");
    
    int len= sizeof(struct sr_ethernet_hdr)+sizeof(struct ip)+sizeof(struct ospfv2_hdr)+sizeof(struct ospfv2_hello_hdr);
    uint8_t* outPkt = ((uint8_t*)malloc(len));
    
    struct ospfv2_hello_packet* hello_pkt = (struct ospfv2_hello_packet*)arg;
    struct sr_ethernet_hdr* e_hdr= ((struct sr_ethernet_hdr*)outPkt);
    struct ip* ip_hdr= ((struct ip*)(outPkt+sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_hdr* ospf_hdr=((struct ospfv2_hdr*)(outPkt + sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_hello_hdr* hello_hdr = (struct ospfv2_hello_hdr*)(outPkt + sizeof(struct ospfv2_hdr)+ sizeof(struct ip) + sizeof(struct sr_ethernet_hdr));
    
    //Initialise ethernet header here
    memset(e_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(e_hdr->ether_shost,hello_pkt->daddr,ETHER_ADDR_LEN);
    e_hdr->ether_type= htons(ETHERTYPE_IP);
    
    //Initialise IP header here
    ip_hdr->ip_dst.s_addr= htonl(OSPF_AllSPFRouters);
    ip_hdr->ip_src.s_addr= hello_pkt->iface->ip;
    ip_hdr->ip_p = 89;
    ip_hdr->ip_v=4;
    ip_hdr->ip_hl=5;
    ip_hdr->ip_len= htons((sizeof(ip_hdr))+ sizeof(ospf_hdr)+ sizeof(hello_hdr));
    ip_hdr->ip_tos=0;
    ip_hdr->ip_off=0;
    ip_hdr->ip_ttl=64;
    setIPchecksum(ip_hdr);
    
    //Initialise OSPF hello packet
    hello_hdr->helloint = OSPF_DEFAULT_HELLOINT;
    hello_hdr->padding=0;
    hello_hdr->nmask=hello_pkt->iface->mask;

    //Initialize OSPF header here
    ospf_hdr->version=2;
    ospf_hdr->type=OSPF_TYPE_HELLO;
    ospf_hdr->rid= router_addr.s_addr;
    ospf_hdr->len = htons(sizeof(hello_hdr)+sizeof(ospf_hdr));
    ospf_hdr->audata=0;
    ospf_hdr->autype=0;
    ospf_hdr->aid=0;
    
    memcpy(outPkt, e_hdr , sizeof(struct sr_ethernet_hdr));
    memcpy(outPkt + sizeof(struct sr_ethernet_hdr),ip_hdr,sizeof(struct ip));
    memcpy(outPkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip), ospf_hdr, sizeof(struct ospfv2_hdr));
    memcpy(outPkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr), hello_hdr, sizeof(struct ospfv2_hello_hdr));
    
    ospf_hdr->csum=0;
    ospf_hdr->csum = htons(compute_checksum(ospf_hdr, (sizeof(struct ospfv2_hdr)-8)));
	   
    sr_send_packet(hello_pkt->sr,outPkt, len,hello_pkt->iface->name);
    
    return NULL;
    
    
}
/*--------------------------------------------------------------------------------------------------------------
 * Method:void* linkup(void* arg)
 * Scope:  Global
 *
 *-------------------------------------------------------------------------------------------------------------*/
void* linkup(void* arg)
{
    
    struct ospfv2_lsu_update* lsu_update=(struct ospfv2_lsu_update*)arg;
    struct sr_instance* sr;
    sr=lsu_update->sr;

    printf("Going to construct the LSU packet\n");
    
    struct sr_if* if_walker;
    if_walker= lsu_update->sr->if_list;
    
    int num_routes=0;
    int i=0;
    
    while(if_walker!=NULL)
    {
        num_routes++;
        
        if(strcmp(if_walker->name, lsu_update->iface->name)==0)
        {
            if_walker->neighbour_rid=lsu_update->iface->neighbour_rid;
            if_walker->neighbour_ip=lsu_update->iface->neighbour_ip;
            memcpy(if_walker->neighbour_addr,lsu_update->iface->addr,ETHER_ADDR_LEN);
        }
        
        if_walker=if_walker->next;
    }
    
    int len= sizeof(struct sr_ethernet_hdr)+sizeof(struct ip)+sizeof(struct ospfv2_hdr)+sizeof(struct ospfv2_lsu_hdr)+ (sizeof(struct ospfv2_lsu)*num_routes);
    uint8_t* outPkt;
    outPkt= ((uint8_t*)malloc(len));
    
    struct sr_ethernet_hdr* e_hdr= ((struct sr_ethernet_hdr*)outPkt);
    struct ip* ip_hdr= ((struct ip*)(outPkt+sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_hdr* ospf_hdr=((struct ospfv2_hdr*)(outPkt + sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_lsu_hdr* lsu_hdr=((struct ospfv2_lsu_hdr*)(outPkt + sizeof(struct ospfv2_hdr)+sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_lsu* lsa_hdr=((struct ospfv2_lsu*)(outPkt +(sizeof(struct ospfv2_lsu*)*num_routes)+sizeof(struct ospfv2_lsu_hdr)+ sizeof(struct ospfv2_hdr)+sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    
    //Ethernet Header
    e_hdr->ether_type=htons(ETHERTYPE_IP);
    
    //IP header
    ip_hdr->ip_hl=5;
    ip_hdr->ip_v=4;
    ip_hdr->ip_tos=0;
    ip_hdr->ip_len= htons((sizeof(ip_hdr))+ sizeof(ospf_hdr)+ sizeof(lsu_hdr)+ sizeof(lsa_hdr)*num_routes);
    ip_hdr->ip_off=0;
    ip_hdr->ip_ttl=64;
    ip_hdr->ip_p = 89;
    
    //OSPF Header
    ospf_hdr->version= OSPF_V2;
    ospf_hdr->type=OSPF_TYPE_LSU;
    ospf_hdr->len = htons(sizeof(lsa_hdr)*num_routes+sizeof(lsu_hdr)+sizeof(ospf_hdr));
    ospf_hdr->rid= lsu_update->rid;
    ospf_hdr->aid=ntohs(0);
    
    //LSU Header
    sr->seqno= sr->seqno+1;
    lsu_hdr->seq= htons(sr->seqno);
    lsu_hdr->ttl=OSPF_MAX_LSU_TTL ;
    lsu_hdr->num_adv= htonl(num_routes);
    
    memcpy(outPkt, e_hdr , sizeof(struct sr_ethernet_hdr));
    memcpy(outPkt + sizeof(struct sr_ethernet_hdr),ip_hdr,sizeof(struct ip));
    memcpy(outPkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip), ospf_hdr, sizeof(struct ospfv2_hdr));
    memcpy(outPkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr), lsu_hdr, sizeof(struct ospfv2_lsu_hdr));
    
    
    if_walker= lsu_update->sr->if_list;
    
    i=0;

    while(if_walker!=NULL)
    {
	
     lsa_hdr=((struct ospfv2_lsu*)(outPkt +(sizeof(struct ospfv2_lsu))*i+sizeof(struct ospfv2_lsu_hdr)+ sizeof(struct ospfv2_hdr)+sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));

		if(strcmp(if_walker->name,"eth0")==0 && (strcmp(sr->host,"vhost1")==0))
		{
				lsa_hdr->subnet =0;
				lsa_hdr->mask=0;
				lsa_hdr->rid=0;
			
		}

		else
		{
        		lsa_hdr->subnet= (if_walker->ip & if_walker->mask);
        		lsa_hdr->mask = if_walker->mask;
        		lsa_hdr->rid= if_walker->neighbour_rid;
        	}

       sr->num_adv++;
       
       memcpy(outPkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) +sizeof(struct ospfv2_hdr)+sizeof(struct ospfv2_lsu_hdr) + (sizeof(struct ospfv2_lsu))*i, lsa_hdr,sizeof(struct ospfv2_lsu));
       i++;
        
        if_walker=if_walker->next;
    }

    if_walker= lsu_update->sr->if_list;
    
    
    while(if_walker!=NULL)
    {
        memcpy(e_hdr->ether_dhost,if_walker->neighbour_addr,ETHER_ADDR_LEN);
        memcpy(e_hdr->ether_shost,if_walker->addr, ETHER_ADDR_LEN);
        
        ip_hdr->ip_dst.s_addr=if_walker->neighbour_ip;
        ip_hdr->ip_src.s_addr= if_walker->ip;
        
        ospf_hdr->aid=0;
        ospf_hdr->autype=0;
        ospf_hdr->csum=0;
        ospf_hdr->csum=htons(compute_checksum(ospf_hdr, (sizeof(struct ospfv2_hdr)-8)));
        
        
        setIPchecksum(ip_hdr);
        

	struct in_addr router_rid;
        router_rid.s_addr=ip_hdr->ip_dst.s_addr;
        
	printf("Sending the LSU packet\n");
       
        sr_send_packet(sr,outPkt, len,if_walker->name);
        
        if_walker=if_walker->next;
    }
    
    lsu_status=0;
    return NULL;
    
    
}
/*--------------------------------------------------------------------------------------------------------------
 * Method: void handle_hello_pkts(struct sr_instance* sr, uint8_t* outPkt, unsigned int len, struct sr_if* interf)
 * Scope:  Global
 * Handle incoming hello packets
 *-------------------------------------------------------------------------------------------------------------*/
void handle_hello_pkts(struct sr_instance* sr, uint8_t* outPkt, unsigned int len, char* interface,struct sr_if* interf)
{
    printf("Handling the hello packet\n");
    
    int newneighbour=1;
    struct sr_ethernet_hdr* e_hdr= ((struct sr_ethernet_hdr*)outPkt);
    struct ip* ip_hdr= ((struct ip*)(outPkt+sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_hdr* ospf_hdr=((struct ospfv2_hdr*)(outPkt + sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_hello_hdr* hello_pkt = (struct ospfv2_hello_hdr*)(outPkt + sizeof(struct ospfv2_hdr)+ sizeof(struct ip) + sizeof(struct sr_ethernet_hdr));
    struct sr_if* iface=sr->if_list;	    

    while(iface!=NULL)
    {
        if(iface->ip > router_addr.s_addr)
        router_addr.s_addr = iface->ip;
            
        iface=iface->next;
    }
      
    sr->rid=router_addr.s_addr;

     if(hello_pkt->nmask != interf->mask)
     {
     printf("Masks do not match!! Packet dropped!!\n");
     return;
     }
    
    if(hello_pkt->helloint != OSPF_DEFAULT_HELLOINT)
    {
        printf("Hello time intervals do not match!! Packets dropped\n");
        return;
    }
    
    
    
    if(interf->neighbour_ip == ip_hdr->ip_src.s_addr)
    {
        printf("Interface neighbor exists!!\n");
	gettimeofday(&interf->neighbour_helloint, NULL);
	
    	neighbor_timer=1;  
	 
    }
    
    else
    {
          printf("Interface neighbor doesn't exist!! Adding neighbors\n");
          interf->neighbour_ip = ip_hdr->ip_src.s_addr;
          memcpy(interf->neighbour_addr,e_hdr->ether_shost,ETHER_ADDR_LEN);
          interf->neighbour_rid=ospf_hdr->rid;
          gettimeofday(&interf->neighbour_helloint, NULL);
	  neighbor_timer=1;    

          lsu_status=1;

          struct ospfv2_lsu_update* lsu_update=((struct ospfv2_lsu_update*)malloc(sizeof(struct ospfv2_lsu_update)));
          lsu_update->sr=sr;
          lsu_update->iface=interf;
          lsu_update->rid=sr->rid;
	   
	   printf("Link State Update\n");
           pthread_create(&linkupdate, NULL, linkup, lsu_update);
	   gettimeofday(&(sr->lsuint), NULL);
     }
}


/*--------------------------------------------------------------------------------------------------------------
 * Method:void* linkStateUpdate(void* arg)
 * Scope:  Global
 *
 *-------------------------------------------------------------------------------------------------------------*/

void* linkStateUpdate(void* arg)
{
    struct sr_instance* sr= (struct sr_instance*)arg;
    printf("Going to construct the LSU packet\n");
    struct sr_if* if_walker=sr->if_list;
    int num_routes=0;
    
    while(if_walker!=NULL)
    {
        num_routes++;
        if_walker=if_walker->next;
    }
    
    int len= sizeof(struct sr_ethernet_hdr)+sizeof(struct ip)+sizeof(struct ospfv2_hdr)+sizeof(struct ospfv2_lsu_hdr)+ (sizeof(struct ospfv2_lsu)*num_routes);
    uint8_t* outPkt;
    outPkt= ((uint8_t*)malloc(len));
    
    struct sr_ethernet_hdr* e_hdr= ((struct sr_ethernet_hdr*)outPkt);
    struct ip* ip_hdr= ((struct ip*)(outPkt+sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_hdr* ospf_hdr=((struct ospfv2_hdr*)(outPkt + sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_lsu_hdr* lsu_hdr=((struct ospfv2_lsu_hdr*)(outPkt + sizeof(struct ospfv2_hdr)+sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_lsu* lsa_hdr=((struct ospfv2_lsu*)(outPkt +(sizeof(struct ospfv2_lsu*)*num_routes)+sizeof(struct ospfv2_lsu_hdr)+ sizeof(struct ospfv2_hdr)+sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    struct sr_if* iface;
    
    //Ethernet Header
    e_hdr->ether_type=htons(ETHERTYPE_IP);
    
    //IP header
    ip_hdr->ip_hl=5;
    ip_hdr->ip_v=4;
    ip_hdr->ip_tos=0;
    ip_hdr->ip_len= htons((sizeof(ip_hdr))+ sizeof(ospf_hdr)+ sizeof(lsu_hdr)+ sizeof(lsa_hdr)*num_routes);
    ip_hdr->ip_off=0;
    ip_hdr->ip_ttl=64;
    ip_hdr->ip_p = 89;
    
    //OSPF Header
    ospf_hdr->version= OSPF_V2;
    ospf_hdr->type=OSPF_TYPE_LSU;
    ospf_hdr->len = htons(sizeof(lsa_hdr)*num_routes+sizeof(lsu_hdr)+sizeof(ospf_hdr));
    ospf_hdr->rid=sr->rid;
    ospf_hdr->aid=ntohs(0);
    
    //LSU Header
    sr->seqno=sr->seqno+1;
    lsu_hdr->seq= htons(sr->seqno);
    lsu_hdr->ttl=OSPF_MAX_LSU_TTL ;
    lsu_hdr->num_adv= htonl(num_routes);
    
    memcpy(outPkt, e_hdr , sizeof(struct sr_ethernet_hdr));
    memcpy(outPkt + sizeof(struct sr_ethernet_hdr),ip_hdr,sizeof(struct ip));
    memcpy(outPkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip), ospf_hdr, sizeof(struct ospfv2_hdr));
    memcpy(outPkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr), lsu_hdr, sizeof(struct ospfv2_lsu_hdr));
    
    int i=0;
    iface= sr->if_list;
    while(iface!=NULL)
    {
	lsa_hdr=((struct ospfv2_lsu*)(outPkt +(sizeof(struct ospfv2_lsu))*i+sizeof(struct ospfv2_lsu_hdr)+ sizeof(struct ospfv2_hdr)+sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
       
		if(strcmp(iface->name,"eth0")==0 && (strcmp(sr->host,"vhost1")==0))
                {
                        	lsa_hdr->subnet =0;
                        	lsa_hdr->mask=0;
                        	lsa_hdr->rid=0;
                }

	else
	{
		lsa_hdr->subnet= (iface->ip & iface->mask);
        	lsa_hdr->mask = iface->mask;
     		lsa_hdr->rid= iface->neighbour_rid;
        }

	sr->num_adv++;
        
        memcpy(outPkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr)+sizeof(struct ospfv2_lsu_hdr) + (sizeof(struct ospfv2_lsu)*i), lsa_hdr,sizeof(struct ospfv2_lsu));
        i++;
        
        iface=iface->next;
    }
    
    iface=sr->if_list;
    
    while(iface!=NULL)
    {
        memcpy(e_hdr->ether_dhost,iface->neighbour_addr,ETHER_ADDR_LEN);
        memcpy(e_hdr->ether_shost,iface->addr, ETHER_ADDR_LEN);
        ip_hdr->ip_dst.s_addr=iface->neighbour_ip;
        ip_hdr->ip_src.s_addr= iface->ip;
        
        ospf_hdr->aid=0;
        ospf_hdr->autype=0;
        ospf_hdr->csum=0;
        ospf_hdr->csum=htons(compute_checksum(ospf_hdr, (sizeof(struct ospfv2_hdr)-8)));
        
        
        setIPchecksum(ip_hdr);
        sr_send_packet(sr,outPkt, len,iface->name);
        
        iface=iface->next;
    }
    
    return NULL;
}

/*------------------------------------------------------------------------------------------------------------------------------
 * Method:void search_routes(struct sr_instance*sr,uint32_t sender_ip, struct timeval time)
 * Scope:  Global
 *------------------------------------------------------------------------------------------------------------------------------*/
void search_routes(struct sr_instance* sr,uint32_t sender_ip, struct timeval time,struct timeval past,int n)
{
    struct lsa_packet* lsa_record=0;
	
	    
    if(sr->adv == 0)
    {
        printf("No routes\n");
        return;
    }
    
    lsa_record = sr->adv;
    struct  lsa_packet* new_record;
 
    if(n==0)
    {
	 pwospf_lock(sr->ospf_subsys);
        /* lsa_record is pointing to the first node
        Start with second node and traverse the whole list*/
        while(lsa_record->next!=0)
        {
            //lsa_record is parent node. 
            //set new_record to point to child node of lsa_record
            //now new_record is current node.
            new_record = lsa_record->next;
            //check if current node (new_record) is candidate for deletion
            if(new_record->ip == sender_ip && sender_ip>0 && new_record->time.tv_sec == time.tv_sec)
            {
                printf("Removing topology\n");
                //update parent's child pointer to be equal to child of current node
                lsa_record->next = new_record->next;
                free(new_record);				
		    }
            else 
            {
                //just move to the next node
                lsa_record = lsa_record->next;
            }
        }
        
        /* Check the first node */
        lsa_record = sr->adv;
        if(lsa_record->ip == sender_ip && sender_ip>0 && lsa_record->time.tv_sec == time.tv_sec)
        {
            lsa_record=sr->adv->next;
            free(sr->adv);
            sr->adv = lsa_record;
            printf("First element has been removed\n");
        }
	
	

	pwospf_unlock(sr->ospf_subsys);
	
	if(lsa_record==0)
	return;
    }		
	

    else if(n==1)
    {
		while(lsa_record!=0)
		{
			if(lsa_record->rid==sender_ip && lsa_record->time.tv_sec == past.tv_sec)
			lsa_record->time.tv_sec = time.tv_sec;
			
			lsa_record=lsa_record->next;
		}

    }

	struct lsa_packet* pkt=sr->adv;

	if(pkt==0)
	printf("EMPTY\n");

}

/*------------------------------------------------------------------------------------------------------------------------------
 * Method:void search(struct database* record,struct in_addr router_rid,struct in_addr subnet,struct in_addr mask,struct in_addr rid,uint16_t seqno)
 * Scope:  Global
 *------------------------------------------------------------------------------------------------------------------------------*/

int search_database(struct sr_instance* sr,struct in_addr sender_rid,uint8_t* packet, uint16_t seqno)
{
    /*sender ip and seq no matches, drop packet
      Packet & sender ip match, update seqno
      soucer ip matches, check lsa rid but mask does not macth, do no update database*/
    
   printf("Searching the packet\n");
   int counter=0;
   struct  database* db_record = 0;
   struct lsa_packet* lsa = sr->adv;
   struct lsa_packet* temp;

   int n=0;   	
   
  if(sr->Database == 0 || sr->adv == 0)
  {
    printf("Database empty\n");
    return counter;
  }

  

   db_record = sr->Database;

   while(db_record!=NULL)
   {
            if(sender_rid.s_addr== db_record->rid.s_addr)
           {
               
		if(memcmp(db_record->packet,packet,sizeof(packet))==0)
		{
                   if((db_record->seqno)==htons(seqno))
                   {
                       counter=1;
                       break;
                   }

		    else if((db_record->seqno)!=htons(seqno))
	            {
                       counter =2;
                       struct timeval past;
                       past.tv_sec= db_record->time.tv_sec;
                        db_record->seqno = htons(seqno);
                       gettimeofday(&(db_record->time),NULL);
                       search_routes(sr,db_record->rid.s_addr,db_record->time,past,1);
                       break;
                    }
                 }
            }
	db_record=db_record->next;
    }

    return counter;
}
/*------------------------------------------------------------------------------------------------------------------------------
 * Method:void add_routes(sr,outPkt)
 * Scope:  Global
 *------------------------------------------------------------------------------------------------------------------------------*/
void add_routes(struct sr_instance* sr,uint8_t* outPkt,uint32_t sender_ip, struct timeval time)
{
    struct ospfv2_hdr* ospf_hdr=((struct ospfv2_hdr*)(outPkt + sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_lsu* lsa_hdr;
    struct lsa_packet* packet = 0;
    
    printf("Adding routes to the topology\n");
    
    for(int i=0;i<3;i++)
    {
        lsa_hdr=((struct ospfv2_lsu*)(outPkt +(sizeof(struct ospfv2_lsu)*i)+sizeof(struct ospfv2_lsu_hdr)+ sizeof(struct ospfv2_hdr)+sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
        
	 
        if(sr->adv == 0)
        {
            sr->adv = (struct lsa_packet*)malloc(sizeof(struct lsa_packet));
            sr->adv->next = 0;

            sr->adv->rid=ospf_hdr->rid;
	    struct in_addr rid;
            rid.s_addr=sr->adv->rid;
            
	
	    sr->adv->ip=sender_ip;
	    rid.s_addr=sr->adv->ip;
            
		
            sr->adv->subnet= lsa_hdr->subnet;
	    rid.s_addr=sr->adv->subnet;
            
	    sr->adv->mask= lsa_hdr->mask;
	    rid.s_addr=sr->adv->mask;
            
       	    
	    sr->adv->neighbour_rid=lsa_hdr->rid;
            rid.s_addr=sr->adv->neighbour_rid;
            
            
            sr->adv->time.tv_sec = time.tv_sec;
            sr->adv->time.tv_usec = time.tv_usec;

	    printf("Adding routes to the topology\n\n");
        }
        
        
	  else{
            packet=sr->adv;
        
            while(packet->next)
            {packet = packet->next; }
            packet->next = (struct lsa_packet*)malloc(sizeof(struct lsa_packet));
            packet = packet->next;
            packet->next=0;

            packet->rid=ospf_hdr->rid;

            struct in_addr rid;
            rid.s_addr=packet->rid;
            
            packet->ip=sender_ip;
            rid.s_addr=packet->ip;
            
            packet->subnet= lsa_hdr->subnet;
            rid.s_addr=packet->subnet;
           
            packet->mask= lsa_hdr->mask;
            rid.s_addr=packet->mask;
            
            packet->neighbour_rid=lsa_hdr->rid;
            rid.s_addr=packet->neighbour_rid;
           
            packet->time.tv_sec = time.tv_sec;
            packet->time.tv_usec = time.tv_usec;

	    printf("Adding routes to the topology\n\n");
        }
    }
}
/*------------------------------------------------------------------------------------------------------------------------------
 * Method:void add_database(struct database* record,struct in_addr router_rid,struct in_addr subnet,struct in_addr mask,struct in_addr rid,uint16_t seqno)
 * Scope:  Global	
 *------------------------------------------------------------------------------------------------------------------------------*/
void add_database(struct sr_instance* sr,struct in_addr sender_rid,uint8_t* packet,struct in_addr sender_ip, uint16_t seqno,uint8_t* outPkt)
{
    
    struct database* db_record = 0;

    /* -- empty list special case -- */
    if(sr->Database == 0)
    {
        sr->Database = (struct database*)malloc(sizeof(struct database));
        sr->Database->next = 0;
        
	int length = sizeof(struct ospfv2_lsu)*3;
        sr->Database->packet = ((uint8_t*)malloc(length));
		
	memcpy(sr->Database->packet, packet, sizeof(packet));
	
        sr->Database->rid.s_addr=sender_rid.s_addr;
        sr->Database->sender_ip.s_addr=sender_ip.s_addr;
	
        sr->Database->seqno=htons(seqno);
	sr->Database->my_rid=sr->rid;
        gettimeofday(&(sr->Database->time),NULL);
	add_routes(sr,outPkt,sender_ip.s_addr,sr->Database->time);
        
	printf("Record successfully added in the topology table!!!\n\n");
	
	db_init++;
	return;
    }

    /* -- find the end of the list -- */
    db_record = sr->Database;
    while(db_record->next)
    {db_record = db_record->next; }

    db_record->next = (struct database*)malloc(sizeof(struct database));
    db_record = db_record->next;
    
    int length = sizeof(struct ospfv2_lsu)*3;
    db_record->packet =((uint8_t*)malloc(sizeof(length)));
    memcpy(db_record->packet, packet, sizeof(packet));

    db_record->my_rid=sr->rid;
    db_record->rid.s_addr = sender_rid.s_addr;
    db_record->sender_ip.s_addr=sender_ip.s_addr;

    db_record->seqno =htons(seqno);
    gettimeofday(&(db_record->time),NULL);

    add_routes(sr,outPkt,sender_ip.s_addr,db_record->time);
    db_record->next = 0;
}

/*------------------------------------------------------------------------------------------------------------------------------
 * Method:int search_topo(struct sr_instance* sr,struct lsa_packet* packet)
 * Scope:  Global
 *------------------------------------------------------------------------------------------------------------------------------*/
int search_topo(struct sr_instance* sr,struct lsa_packet* packet)
{
    struct lsa_packet* topo = sr->adv;
    int count_hop = 0;
    
    while(topo!=NULL)
    {
        if(topo->subnet == packet->subnet)
        {
            
                count_hop++;
        }
        
        topo = topo->next;
    }
    
    return count_hop;
}

/*------------------------------------------------------------------------------------------------------------------------------
 * Method:void my_algo(struct sr_instance* sr)
 * Scope:  Global
 *------------------------------------------------------------------------------------------------------------------------------*/
void my_algo(struct sr_instance* sr)
{

struct lsa_packet* topology=sr->adv;
struct sr_if* if_Walker=sr->if_list;
sr->routing_table=0;
	
	while(if_Walker!=NULL)
   	{
        	if(strcmp(if_Walker->name,"eth0")==0)
                {
			 if(strcmp(sr->host,"vhost1")==0)
			 {	
				FILE* fp;
				char  line[BUFSIZ];
				char  dest[32];
				char  gw[32];
				char  mask[32];
				char  iface[32];
				struct in_addr dest_addr;
				struct in_addr gw_addr;
			        struct in_addr mask_addr;
				
				fp = fopen("rtable.net","r");
			    
				while( fgets(line,BUFSIZ,fp) != 0)
				{
					if (EOF == sscanf(line,"%s %s %s %s",dest,gw,mask,iface)) break;
					
					if(inet_aton(dest,&dest_addr) == 0)
					{ 
					    fprintf(stderr,
						    "Error loading routing table, cannot convert %s to valid IP\n",
						    dest);
					    return -1; 
					}

					if(inet_aton(gw,&gw_addr) == 0)
					{ 
					    fprintf(stderr,
						    "Error loading routing table, cannot convert %s to valid IP\n",
						    gw);
					    return -1; 
					}

					if(inet_aton(mask,&mask_addr) == 0)
					{ 
					    fprintf(stderr,
						    "Error loading routing table, cannot convert %s to valid IP\n",
						    mask);
					    return -1; 
					}

					sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,if_Walker->name);
				}
	                  }
        	    }		

		
		else if((strcmp(sr->host,"vhost2")==0 && strcmp(if_Walker->name,"eth1")==0)|| (strcmp(sr->host,"vhost3")==0 && strcmp(if_Walker->name,"eth1")==0))
                {
                        uint32_t subnet;
                        subnet= if_Walker->ip & if_Walker->mask;
                        
			struct in_addr dest_addr;
			dest_addr.s_addr = if_Walker->neighbour_ip;
			struct in_addr gw_addr;
			gw_addr.s_addr = subnet;
			struct in_addr mask_addr;
			mask_addr.s_addr= if_Walker->mask;
			
			sr_add_rt_entry(sr,gw_addr,dest_addr,mask_addr,if_Walker->name);        
			
                }

                if_Walker=if_Walker->next;
        }

    while(topology!=NULL)
    {
	if_Walker = sr->if_list;
	
        int count_hop=0;
        
        while(if_Walker!=NULL)
        {
             if(if_Walker->neighbour_ip == topology->ip)
             {
                 count_hop = search_topo(sr, topology);
 
		 struct in_addr dest_addr;
		 dest_addr.s_addr = topology-> subnet;
		 struct in_addr gw_addr;
		 gw_addr.s_addr = if_Walker->neighbour_ip;  
		 struct in_addr mask_addr;
		 mask_addr.s_addr= topology->mask;
			
                 if(count_hop==1)
		 {
			sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,if_Walker->name);
		 }

                 else if(count_hop>1)
                 {
                     if(strcmp(if_Walker->name,"eth2")==0)
		     {
			sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,if_Walker->name);
		     }
                 }
             }

	     	                 
             if_Walker = if_Walker->next;
         }
		
        topology= topology->next;
    }
	
    printf("*******MY ROUTING TABLE**************\n");
    sr_print_routing_table(sr);
}

/*------------------------------------------------------------------------------------------------------------------------------
 * Method:void* handle_lsu_pkts(struct sr_instance* sr, uint8_t* outPkt, unsigned int len, char* interface,struct sr_if* interf)
 * Scope:  Global
 * Handlink LSU packets
 *------------------------------------------------------------------------------------------------------------------------------*/
void* handle_lsu_pkts(struct sr_instance* sr, uint8_t* outPkt, unsigned int len, char* interface,struct sr_if* interf)
{
    printf("Handling the Link State update packet\n");


    struct sr_ethernet_hdr* e_hdr= ((struct sr_ethernet_hdr*)outPkt);
    struct ip* ip_hdr= ((struct ip*)(outPkt+sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_hdr* ospf_hdr=((struct ospfv2_hdr*)(outPkt + sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_lsu_hdr* lsu_hdr=((struct ospfv2_lsu_hdr*)(outPkt + sizeof(struct ospfv2_hdr)+sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_lsu* lsa_hdr;
    struct ospfv2_lsu* temp;
    struct sr_if* iface=sr->if_list;
    struct lsa_packet* pkt=sr->adv;

    int length = sizeof(struct ospfv2_lsu)* 3; 
    uint8_t* packet;
    packet= ((uint8_t*)malloc(length));

    while(iface!=NULL)
    {
        if(iface->ip > router_addr.s_addr)
        router_addr.s_addr = iface->ip;
            
        iface=iface->next;
    }
      
    sr->rid=router_addr.s_addr;	
  
    iface = sr->if_list;
        
    int checker=0;

    for(int i=0;i<3;i++)
    {
    lsa_hdr=((struct ospfv2_lsu*)(outPkt +(sizeof(struct ospfv2_lsu)*i)+sizeof(struct ospfv2_lsu_hdr)+ sizeof(struct ospfv2_hdr)+sizeof(struct ip)+ sizeof(struct sr_ethernet_hdr)));
    struct in_addr rid;
    rid.s_addr=lsa_hdr->rid;
	
    if(lsa_hdr->rid == sr->rid)
    checker++;

    memcpy(packet+(sizeof(struct ospfv2_lsu)*i), lsa_hdr,sizeof(struct ospfv2_lsu));
    }

    struct in_addr sender_rid;
    struct in_addr sender_ip;
    sender_ip.s_addr=ip_hdr->ip_src.s_addr;
	
    int check=0;
    while(iface!=NULL)
   {
	if(iface->neighbour_rid==ospf_hdr->rid)
	check++;

	iface=iface->next;
   } 

   iface=sr->if_list;
        
   sender_rid.s_addr = ospf_hdr->rid;
    
   if(sr->rid==ospf_hdr->rid)
    {
        printf("Packet originated from this router!! Packet dropped\n\n");
        return;
    }
   
   if(checker == 0)
    {
        printf("My neighbour has not discovered me\n");
        return;
    }
   

    int ct = search_database(sr,sender_rid,packet,lsu_hdr->seq);
    if(ct==1)
    {
        printf("Sequence Number not updated!! Packet dropped!!\n");
        return;
    }
    
    if(ct==2)
    {
        printf("Packet already received from the sender host!!Sequence number updated!!Packet dropped!!\n");
        return;
    }

    if(sr->rid==ospf_hdr->rid)
    {
        printf("Packet originated from this router!! Packet dropped\n\n");
        return;
    }   

    if(check==0)
    {
	printf("Neighbor not yet discovered!!Hello packet not received\n");
	return;
    }

    
    else if(ct==0)
    {

        printf("Adding to the database\n");
        add_database(sr,sender_rid,packet,sender_ip,lsu_hdr->seq,outPkt);
	my_algo(sr);
    }
	
    iface=sr->if_list;
    
    //Sending link state flooding to all the neighbors of the router
    while(iface!=NULL)
    {
	 
        if(iface->neighbour_ip==ip_hdr->ip_src.s_addr)
        {
            struct in_addr rid;
            rid.s_addr=iface->neighbour_rid;
            printf("Packet forwarded by this router % s!! Packet dropped\n\n", inet_ntoa(rid));
            	
        }

        else{ 
		
		if(ip_hdr->ip_ttl>1){
                
                printf("Link state flooding\n");
                memcpy(e_hdr->ether_dhost,iface->neighbour_addr,ETHER_ADDR_LEN);
                memcpy(e_hdr->ether_shost,iface->addr,ETHER_ADDR_LEN);
         
                ip_hdr->ip_dst.s_addr=iface->neighbour_ip;
                ip_hdr->ip_src.s_addr= iface->ip;
                ip_hdr->ip_ttl= ip_hdr->ip_ttl - 1;
                
                lsu_hdr->ttl = lsu_hdr->ttl - 1;
                
                ospf_hdr->csum=0;
                ospf_hdr->csum=htons(compute_checksum(ospf_hdr, (sizeof(struct ospfv2_hdr)-8)));
                
                setIPchecksum(ip_hdr);
                printf("Sending the LSU packet to my  neighbour\n\n");
                sr_send_packet(sr,outPkt, len,iface->name);
            }
            
        }
        
        iface=iface->next;
    } 
	

}

/*--------------------------------------------------------------------------------------------------------------
 * Method: void handle_pwosf_packet(struct sr_instance* sr,uint8_t * outPkt,unsigned int len,char* interface,struct sr_ethernet_hdr * eth_hdr,struct sr_if * interf)
 * Scope:  Global
 *
 *-------------------------------------------------------------------------------------------------------------*/

void handle_pwosf_packet(struct sr_instance* sr,uint8_t* outPkt,unsigned int len,char* interface,struct sr_if* interf)
{
    
    printf("--> Received pwospf packet of length %d\n",len);
    
    struct ospfv2_hdr* ospf_hdr = (struct ospfv2_hdr*)(outPkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    struct ospfv2_hello_hdr* hello_pkt = (struct ospfv2_hello_hdr*)(outPkt + sizeof(struct sr_ethernet_hdr)+ sizeof(struct ip)+ sizeof(struct ospfv2_hdr));
    
    printf("--> Received pwospf packet of length  %d\n",len);
    if(ospf_hdr->version!=2)
    {
        printf("Version ID doesn't match \n");
        return;
    }
    
    uint16_t checksum = ospf_hdr->csum;
    ospf_hdr->csum=0;
    ospf_hdr->csum = htons(compute_checksum(ospf_hdr, (sizeof(struct ospfv2_hdr)-8)));
    
    if(ospf_hdr->csum != checksum)
    {
        printf("Checksum doesn't match  \n");
        return;
    }
    ospf_hdr->csum= checksum;
    
    if(ospf_hdr->aid!=sr->aid)
    {
        printf("Area ID doesn't match  \n");
        return;
    }
    
    if(ospf_hdr->autype!= sr->autype)
    {
        printf("Authentication type doesn't match  \n");
        return;
    }
    
    if(ospf_hdr->type==OSPF_TYPE_HELLO)
    {
        //Hello Packet
        printf(" HELLO!!\n");
	struct in_addr rid;
        rid.s_addr=ospf_hdr->rid;
        printf("Received packet with RID %s\n",inet_ntoa(rid));

        handle_hello_pkts(sr,outPkt,len,interface,interf);   
    }
    
    else if(ospf_hdr->type==4)
    {
        //Link State Update
        printf("LSU Update handler!!\n");
	
        struct in_addr rid;
        rid.s_addr=ospf_hdr->rid;
        printf("Received packet with RID %s\n",inet_ntoa(rid));

        handle_lsu_pkts(sr,outPkt,len,interface,interf);   
	
    } 
}

/*---------------------------------------------------------------------
 * Method: refres_topo
 *
 * Check topology life
 *
 *---------------------------------------------------------------------*/
void* refresh_topo(void* arg)
{

	struct sr_instance* sr= (struct sr_instance*)arg;
        struct database* db_record=0;
	struct lsa_packet* new_record=0;

    while(1)
    {
    
    	usleep(100000*OSPF_TOPO_ENTRY_TIMEOUT);
		
	db_record = sr->Database;
        if(sr->Database == 0 || sr->adv ==0 ||db_record==0)
        {
               return;
        }
        
        

	struct timeval MAX_TIME;
        MAX_TIME.tv_sec = OSPF_TOPO_ENTRY_TIMEOUT;
	             
        struct timeval current;
        struct timeval result;
	struct timeval past;
	
	past.tv_sec=0;
        gettimeofday(&current, NULL);
	timersub(&current, &(db_record->time), &result);
	

	while(db_record->next!=0)
        {
	   

            pwospf_lock(sr->ospf_subsys);
            new_record = db_record->next;
            
 	   
            if (result.tv_sec >= MAX_TIME.tv_sec && db_record->sender_ip.s_addr>0)
            {
		search_routes(sr,db_record->sender_ip.s_addr,db_record->time,past,0);
                printf("Removing Database\n");
                
                db_record->next = new_record->next;
                free(new_record);				
	    }
            else 
            {
               
                db_record = db_record->next;
            }
	    pwospf_unlock(sr->ospf_subsys);
        }
        
        
        db_record = sr->Database;
        if (result.tv_sec >= MAX_TIME.tv_sec && db_record->sender_ip.s_addr>0)
        {
	    search_routes(sr,db_record->sender_ip.s_addr,db_record->time,past,0);

	    pwospf_lock(sr->ospf_subsys);
            db_record=sr->Database->next;
            free(sr->Database);
            sr->Database = db_record;
            printf("First record in database has been removed\n");
	    pwospf_unlock(sr->ospf_subsys);
        }
   	
	if(db_record==0)
	return;

    };
    
    return NULL;
}
