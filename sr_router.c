/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_pwospf.h"
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

struct sr_icmphdr
{
    unsigned char   icmp_type;
    unsigned char   icmp_code;
    unsigned short  icmp_chksum;
    uint16_t icmp_seq;
    uint16_t icmp_id;
} __attribute__ ((packed)) ;

struct sr_arp_cache *arpHead;
struct sr_packet_cache *packetHead;
struct timeval MAX_TIME;

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);
    
    pwospf_init(sr);
    /* Add initialization code here! */
    
    packetHead = (struct sr_packet_cache *) calloc(1, sizeof(struct sr_packet_cache));
    if (packetHead == NULL) {
        fprintf(stderr, "Fail to allocate memory.\n");
        exit(1);
    }
    
    packetHead->dst_ip = -1;
    packetHead->next = NULL;
    packetHead->len = -1;
    
    arpHead = (struct sr_arp_cache *) calloc(1, sizeof(struct sr_arp_cache));
    if (arpHead == NULL) {
        fprintf(stderr, "Fail to allocate memory.\n");
        exit(1);
    }
        
    arpHead->ip = -1;
    arpHead->time.tv_sec = 0;
    arpHead->next = NULL;
    
    MAX_TIME.tv_sec = 15;
    
} /* -- sr_init -- */

/*-----------------------------------------------------------------------------
 * Method: uint16_t compute_checksum(uint8_t *ip, int len)
 * Scope:  Global
 * Compute the Checksum for both ip and icmp
 *---------------------------------------------------------------------------*/

uint16_t compute_checksum(uint8_t *packet, int len) {
    uint32_t sum = 0;
    uint16_t word;
    
    while (len--) {
        word = (uint16_t) ((*packet << 8) + *(packet+1));
        sum += word;
        packet+=2;
        
        if (sum & 0xFFFF0000) {
            sum &= 0xFFFF;
            sum++;
        }
}
    
    return ~(sum & 0xFFFF);
}

/*-----------------------------------------------------------------------------
 * Method: void setICMPchecksum(struct sr_icmphdr* icmphdr, uint8_t * packet, int len) 
 * Scope:  Global
 * Compute the Checksum for both ip and icmp
 *---------------------------------------------------------------------------*/

void setICMPchecksum(struct sr_icmphdr* icmphdr, uint8_t * packet, int len) {
    uint32_t sum = 0;
    icmphdr->icmp_chksum = 0;
    uint16_t* tmp = (uint16_t *) packet;

    int i;
    for (i = 0; i < len / 2; i++) {
        sum = sum + tmp[i];
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = sum + (sum >> 16);

    icmphdr->icmp_chksum = ~sum;
}

/*-----------------------------------------------------------------------------
 * Method: setIPchecksum(struct ip* ip_hdr)
 * Scope:  Global
 * Compute the Checksum for both ip and icmp
 *---------------------------------------------------------------------------*/


void setIPchecksum(struct ip* ip_hdr) {
    uint32_t sum = 0;
    ip_hdr->ip_sum = 0;

    uint16_t* tmp = (uint16_t *) ip_hdr;

    int i;
    for (i = 0; i < ip_hdr->ip_hl * 2; i++) {
        sum = sum + tmp[i];
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = sum + (sum >> 16);

    ip_hdr->ip_sum = ~sum;
}




/*---------------------------------------------------------------------
 * Method: sr_arp_cache *arp_Cache_Search(uint32_t ip)
 * Scope:  Global
 * Cache the ARP packet
 *---------------------------------------------------------------------*/

struct sr_arp_cache *arp_Cache_Search(uint32_t ip) {
    struct sr_arp_cache *node = arpHead;
    while (node->next != NULL) {
        node = node->next;
        if (ip == node->ip) {
            return node;
        }
    }
    return NULL;
}

/*---------------------------------------------------------------------
 * Method: sr_packet_cache(uint32_t ip)
 * Scope:  Global
 * Cache the ARP packet
 *---------------------------------------------------------------------*/

struct sr_packet_cache* packet_Cache_Search(uint32_t ip){
 	struct sr_packet_cache *node=packetHead;
	while(node->next!=NULL){
	node = node->next;
	if(ip == node->dst_ip)
	{
	return node;
	}
    }
    return NULL;
}
/*---------------------------------------------------------------------
 * Method: int refresh_cache()
 * Scope:  Global
 * Refresh the ARP list
 *---------------------------------------------------------------------*/

int refresh_cache() {
    struct timeval current;
    struct timeval result;
    gettimeofday(&current, NULL);
    struct sr_arp_cache *ref = arpHead;
    while (ref->next != NULL) {
        timersub(&current, &(ref->next->time), &result);
        if (result.tv_sec >= MAX_TIME.tv_sec) {
            printf("Refreshing cache as time has exceeded 15 seconds \n");
            struct sr_arp_cache *tmp = ref->next;
            ref->next = ref->next->next;
            free(tmp);
        }
        if (ref->next != NULL) {
            ref = ref->next;
        }
    }
    return 0;
}

/*---------------------------------------------------------------------
 * Method: int RT_Search(struct sr_rt *entry, uint32_t addr)
 * Scope:  Global
 * Check the routing table for entry
 *---------------------------------------------------------------------*/

int RT_Search(struct sr_rt *entry, uint32_t addr) {
    struct in_addr res_rt, res_addr;
    res_rt.s_addr = entry->dest.s_addr & entry->mask.s_addr;
    res_addr.s_addr = addr & entry->mask.s_addr;
    if (res_rt.s_addr == res_addr.s_addr) {
        return 1;
    }
    return 0;
}

/*---------------------------------------------------------------------
 * Method: int compute_mask_length(uint32_t mask)
 * Scope:  Global
 * Compute the length of the Mask
 *---------------------------------------------------------------------*/

int compute_mask_length(uint32_t mask) {
    int l = 0;
    while (mask > 0) {
        l++;
        mask <<= 1;
    }
    return l;
}


/*------------------------------------------------------------------------------------------------------------
 * Method: create_ip_hdr(uint8_t type, uint8_t ttl, uint8_t protocol, struct in_addr src, struct in_addr dest)
 * Scope:  Global
 * Create an ip header with the given specifications
 *------------------------------------------------------------------------------------------------------------*/

struct ip* create_ip_hdr(uint8_t type, uint8_t ttl, uint8_t protocol, struct in_addr src, struct in_addr dest) {
   
    struct ip* ip_hdr = malloc(20);
    ip_hdr->ip_v = 4;
    ip_hdr->ip_ttl = ttl;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_p = protocol;
    ip_hdr->ip_src = src;
    ip_hdr->ip_dst = dest;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_tos = type;
    
    return ip_hdr;
}

/*------------------------------------------------------------------------------------------------------------
 * Method: create_icmp_hdr(uint8_t type, uint8_t code, uint16_t id, uint16_t seq)
 * Scope:  Global
 * Create an ip header with the given specifications
 *------------------------------------------------------------------------------------------------------------*/

struct sr_icmphdr* create_icmp_hdr(char type, char code, uint16_t id, uint16_t seq) {
    
    struct sr_icmphdr* icmp_hdr = malloc(sizeof(struct sr_icmphdr));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_id = id;
    icmp_hdr->icmp_seq = seq;
    
    uint16_t sum = 0;
    sum = ((type << 8)&0xFF00) + code;
    sum = sum + id + seq;
    
    return icmp_hdr;
}

/*----------------------------------------------------------------------------------------------------------------
 * Method: void icmp_message(struct sr_instance* sr,unsigned int len,char* interface,uint8_t* packet,uint8_t type, uint8_t code)

 * Scope:  Global
 * Handle ICMP error messages
 *----------------------------------------------------------------------------------------------------------------*/

void icmp_message(struct sr_instance* sr,unsigned int len,char* interface,uint8_t* packet,char type, char code)
{
    uint8_t * out_pkt = malloc(sizeof (struct sr_ethernet_hdr) + 64);
    struct sr_ethernet_hdr * out_eth_hdr = (struct sr_ethernet_hdr *) out_pkt;
    struct ip* in_ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));

    memcpy(out_eth_hdr, packet, sizeof (struct sr_ethernet_hdr));
    out_eth_hdr->ether_type = ntohs(ETHERTYPE_IP);
    
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        char tmp = out_eth_hdr->ether_dhost[i];
        out_eth_hdr->ether_dhost[i] = out_eth_hdr->ether_shost[i];
        out_eth_hdr->ether_shost[i] = tmp;
    }
    
        
    struct ip* tmp_ip = create_ip_hdr(0, 20, IPPROTO_ICMP, in_ip_hdr->ip_dst, in_ip_hdr->ip_src);
    struct ip* out_ip_hdr = (struct ip *) (out_pkt + sizeof (struct sr_ethernet_hdr));
    memcpy(out_pkt + sizeof (struct sr_ethernet_hdr), tmp_ip, 20);
    out_ip_hdr->ip_id = in_ip_hdr->ip_id;
    
    /* create and fill an icmp header */
    struct sr_icmphdr * out_icmp = (struct sr_icmphdr *) (out_pkt + sizeof (struct sr_ethernet_hdr) + 20);
    struct sr_icmphdr * tmpicmp = create_icmp_hdr(type, code, 0, 0);
    memcpy(out_icmp, tmpicmp, 8);
    memcpy(((uint8_t *) out_icmp) + 8, in_ip_hdr, in_ip_hdr->ip_hl * 4 + 8);
    
    out_ip_hdr->ip_len = ntohs(28 + in_ip_hdr->ip_hl * 4 + 8);
    
    /* calculate checksums for message */
    setICMPchecksum(out_icmp,out_pkt+ sizeof(struct sr_ethernet_hdr)+20,16+in_ip_hdr->ip_hl*4);
    setIPchecksum(out_ip_hdr);    
  
  /* send message*/
    sr_send_packet(sr, out_pkt, sizeof (struct sr_ethernet_hdr) + 36 + in_ip_hdr->ip_hl * 4, interface);
    
    free(tmpicmp);
    free(out_pkt);
    free(tmp_ip);
}
/*--------------------------------------------------------------------------------------------------------------
 * Method: void handle_arp_reply(struct sr_instance* sr,uint8_t * outPkt,unsigned int len,char* interface,struct sr_ethernet_hdr * eth_hdr,struct sr_if * interf)
 * Scope:  Global
 * Handle ARP request and reply
 *-------------------------------------------------------------------------------------------------------------*/


void handle_arp_reply(struct sr_instance* sr,uint8_t * outPkt,unsigned int len,char* interface,struct sr_ethernet_hdr * eth_hdr,struct sr_if * interf)
{
    
    struct sr_arphdr *arpHdr = (struct sr_arphdr *) (outPkt+14);
    
	if (ntohs(arpHdr->ar_op) == ARP_REQUEST && arpHdr->ar_tip == interf->ip) {
        
        printf("Sending ARP reply ***->\n");
        
        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, interf->addr, ETHER_ADDR_LEN);
        
        arpHdr->ar_op = htons(ARP_REPLY);
        arpHdr->ar_pro= htons(ETHERTYPE_IP);
        arpHdr->ar_hln=ETHER_ADDR_LEN;
        arpHdr->ar_pln= sizeof(uint32_t);
        arpHdr->ar_tip = arpHdr->ar_sip;
        arpHdr->ar_sip = interf->ip;
        
        memcpy(arpHdr->ar_tha, arpHdr->ar_sha, ETHER_ADDR_LEN);
        memcpy(arpHdr->ar_sha, interf->addr, ETHER_ADDR_LEN);
       
        sr_send_packet(sr, outPkt, len, interface);
    }
    
        else if (ntohs(arpHdr->ar_op) == ARP_REPLY && arpHdr->ar_tip == interf->ip) {
	
        struct sr_packet_cache *packet = packetHead;
        uint32_t destination=arpHdr->ar_sip;
        
        while (packet->next != NULL) {
            
            if (packet->next->dst_ip == destination)
            {
                struct sr_ethernet_hdr *outEth =(struct sr_ethernet_hdr *) packet->next->content;
                
                memcpy(outEth->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(outEth->ether_shost, interf->addr, ETHER_ADDR_LEN);
                sr_send_packet(sr, packet->next->content, packet->next->len,interface);
		packet->next->queue= packet->next->queue - 1;

                struct sr_packet_cache *tmp = packet->next;
                
		//delete the packet
                packet->next = packet->next->next;
                free(tmp);
            }
            
            //keep iterating the packet until it has no content
            if (packet->next != NULL) {
                packet = packet->next;
            }
        }
    }

     

    struct sr_arp_cache *ref = arp_Cache_Search(arpHdr->ar_sip);
    if (ref == NULL) {
        if (arpHdr->ar_tip == interf->ip) {
            struct sr_arp_cache *newNode =(struct sr_arp_cache *) calloc(1, sizeof(struct sr_arp_cache));
            
            printf("Caching host addresses in ARP cache \n");
            newNode->ip = arpHdr->ar_sip;
            memcpy(newNode->addr, arpHdr->ar_sha, ETHER_ADDR_LEN);
            gettimeofday(&(newNode->time), NULL);

            //inserting the new node in the arp cache
            newNode->next = arpHead->next;
            arpHead->next = newNode;
        }
    } else {
        gettimeofday(&(ref->time), NULL);
        memcpy(ref->addr, arpHdr->ar_sha, ETHER_ADDR_LEN);
    }

}

/*--------------------------------------------------------------------------------------------------------------
 * Method: void handle_ip_reply(struct sr_instance* sr,uint8_t * outPkt,unsigned int len,char* interface,struct sr_ethernet_hdr * eth_hdr,struct sr_if * interf)
 * Scope:  Global
 * If the ethernet packet is IP, then broadcast ARP if it is not found in the cache, otherwise 
 * check the cache if the host is found. Forward the packet
 *-------------------------------------------------------------------------------------------------------------*/
void handle_ip(struct sr_instance* sr,uint8_t * outPkt,unsigned int len,char* interface,struct sr_ethernet_hdr * eth_hdr,struct sr_if * interf)
{
    struct ip *ip_hdr = (struct ip *) (outPkt+14);
    
    int check = 0;
    struct sr_if *iface= sr->if_list;
    
    while (iface != NULL) 
    {
        if (iface->ip == ip_hdr->ip_dst.s_addr) 
	{
            check = 1;
            break;
        }

        iface = iface->next;
    }
       
        if (check) {
        if (ip_hdr->ip_p == IPPROTO_ICMP) {
            printf("The interface is the required interface!! Packet forwarding not required!!\n");
            
            struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr*) (outPkt + sizeof(struct sr_ethernet_hdr) + ip_hdr->ip_hl*4);
            
            if (ntohs(icmp_hdr->icmp_type) == htons(ICMP_ECHO_REQUEST)) {
                
                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost, interf->addr, ETHER_ADDR_LEN);
                
                struct in_addr tmp = ip_hdr->ip_src;
                ip_hdr->ip_src = ip_hdr->ip_dst;
                ip_hdr->ip_dst = tmp;
                
                icmp_hdr->icmp_type = htons(ICMP_ECHO_REPLY);
                
                icmp_hdr->icmp_chksum = 0;
                uint16_t checksum = compute_checksum(outPkt+34, (len-34)/16);
                icmp_hdr->icmp_chksum = checksum;
                sr_send_packet(sr, outPkt, len, interface);
		}
            if (ntohs(icmp_hdr->icmp_type) == ICMP_ECHO_REPLY) {}
        }

            
            //For handling TCP and UDP messages
            if(ip_hdr->ip_p == 0x0006 || ip_hdr->ip_p ==17)
                icmp_message(sr,len,interface,outPkt,3,3);
    }
    
    else {
        
        //if(ip_hdr->ip_ttl>=1){
        ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
        ip_hdr->ip_sum = 0;
        uint16_t checksum = compute_checksum(outPkt+14, 2 * ip_hdr->ip_hl);
        ip_hdr->ip_sum = htons(checksum);
        
        struct sr_rt *rt_match = sr->routing_table;
        struct sr_rt *match = NULL;
        int rt_match_len = -1;
 
        if (rt_match == NULL) {
            printf("No Routing table found. Packet Dropped.\n");
            return;
        }
        
	while (rt_match != NULL) {
            if (RT_Search(rt_match, ip_hdr->ip_dst.s_addr)) {
                if (compute_mask_length(rt_match->mask.s_addr) > rt_match_len) {
                    rt_match_len = compute_mask_length(rt_match->mask.s_addr);
                    match = rt_match;
                }
            }
            rt_match = rt_match->next;
        }
        
	if ((match == NULL) || (strcmp(match->interface, interface) == 0)) {
	rt_match = sr->routing_table;
		while (rt_match != NULL)
		{
			struct sr_if* if_Walker = sr->if_list;
			while(if_Walker!= NULL)
			{
				if(if_Walker->ip == rt_match->dest.s_addr && rt_match->gw.s_addr !=0)
				{		
					match=rt_match;
				}
				if_Walker= if_Walker->next;
			}
		rt_match = rt_match->next;
		}
        }
        

	if(match==NULL)
	{
		rt_match = sr->routing_table;
		while(rt_match!=NULL)
		{
			if(strcmp(rt_match->interface,"eth2")==0)
			{
				if (compute_mask_length(rt_match->mask.s_addr) > rt_match_len) 
				{
		            		rt_match_len = compute_mask_length(rt_match->mask.s_addr);
		            		match = rt_match;
                		}	
			}

			rt_match = rt_match->next;
		}				
	}


        struct sr_if *outIf = sr_get_interface(sr, match->interface);
        uint32_t nextHopIp;
        if (match->gw.s_addr == 0) {
            nextHopIp = ip_hdr->ip_dst.s_addr;
        }
        else {
            nextHopIp = match->gw.s_addr;
        }
        
        struct sr_arp_cache *arpEntry = arp_Cache_Search(nextHopIp);

        if (arpEntry == NULL) {
	
	 struct sr_packet_cache *pktEntry = packet_Cache_Search(nextHopIp);

	    if(pktEntry==NULL){
            struct sr_packet_cache *node = (struct sr_packet_cache *) calloc(1, sizeof(struct sr_packet_cache));
            node->len = len;
             node->dst_ip = nextHopIp;

	    node->queue= node->queue + 1;
            memcpy(node->content, outPkt, len);
            node->next = packetHead->next;
            packetHead->next = node;}

	   else
		pktEntry->queue= pktEntry->queue + 1;
          
            uint8_t *outPkt2 = (uint8_t *) malloc(sizeof(uint8_t) * 42);
            memset(outPkt2, 0, 42);
            
	    printf("Broadcasting ARP request \n");
            struct sr_ethernet_hdr *outEth = (struct sr_ethernet_hdr *)outPkt2;
            struct sr_arphdr *outArp = (struct sr_arphdr *) (outPkt2 + 14);
            memcpy(outEth->ether_shost, outIf->addr, ETHER_ADDR_LEN);
            memset(outEth->ether_dhost, 0xFF, ETHER_ADDR_LEN);
            outEth->ether_type = htons(ETHERTYPE_ARP);
            outArp->ar_hrd = htons(ARPHDR_ETHER);
            outArp->ar_pro = htons(ETHERTYPE_IP);
            outArp->ar_hln = 0x06;
            outArp->ar_pln = 0x04;
            outArp->ar_op = htons(ARP_REQUEST);
            memcpy(outArp->ar_sha, outIf->addr, ETHER_ADDR_LEN);
            outArp->ar_sip = outIf->ip;
            memset(outArp->ar_tha, 0, ETHER_ADDR_LEN);
            outArp->ar_tip = nextHopIp;
            sr_send_packet(sr, outPkt2, len, match->interface);
        }
        
        else 
	{
            memcpy(eth_hdr->ether_dhost, arpEntry->addr, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, outIf->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, outPkt, len, match->interface);
        }
	
	struct sr_packet_cache *packet=packetHead;

		while(packet->next!=NULL)
		{
			if(packet->next->queue > 5)
			{
				printf("Sending Host Unreachable message\n");
				icmp_message(sr,len,interface,packet->next->content,3,1);
				struct sr_packet_cache* temp= packetHead->next;
				packetHead->next= packetHead->next->next;
				free (temp);
			}
			if(packetHead->next!=NULL)
			packet=packet->next;
		}
	//}
        
        //else
          //  icmp_message(sr,len,interface,outPkt,ICMP_TIME_EXCEEDED,0);
    }
	
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,uint8_t * packet,unsigned int len,char* interface)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    
    refresh_cache();
    printf("*** -> Received packet of length %d \n",len);
    
    struct sr_if *interf = sr_get_interface(sr, interface);

    // Copy of the packet is made because this packet will be utilised beyond this method
    uint8_t *outPkt = (uint8_t *) malloc(sizeof(uint8_t)*len);
    if (outPkt == NULL) return;
    memset(outPkt, 0, len);
    memcpy(outPkt, packet, len);
    
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *) outPkt;
    struct ip *ip_hdr= (struct ip*)(outPkt + sizeof(struct sr_ethernet_hdr));
    uint16_t ethType = ntohs(eth_hdr->ether_type);
	
    if (ethType == ETHERTYPE_ARP) {
        handle_arp_reply(sr,outPkt,len,interface,eth_hdr,interf);
    }
    
    else if(ethType == ETHERTYPE_IP && ip_hdr->ip_p==89)
    {
	handle_pwosf_packet(sr,outPkt,len,interface,interf);
    }

    else if (ethType == ETHERTYPE_IP) {
        handle_ip(sr,outPkt,len,interface,eth_hdr,interf);
        
    }
   
    free(outPkt);
}/* end sr_ForwardPacket */


/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

