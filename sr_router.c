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
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
//#include <sys/types.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

// may not be used
//#define ETH0IP "172.29.9.200"
//#define ETH1IP "172.29.9.198"
//#define ETH2IP "172.29.9.214"
  
// Data Structures //

//struct for ARP table's buffer
struct packet_buffer {
    uint8_t *packet;
  	unsigned int len;
  	char interface[sr_IFACE_NAMELEN];
    struct packet_buffer *next;
};

// Struct for ARP table entries
struct arp_entry {
    unsigned char addr[ETHER_ADDR_LEN];
	int macNotNull;
    struct in_addr ip;
    struct packet_buffer* buffer;
    struct arp_entry *next;
};

struct arp_entry *arp_entry_head;
  
// Static Vars // 
struct sr_rt *routingTable = NULL;
//struct sr_if *interfaceList = NULL;
int rc;

// function headers //
void print_ethFrame(struct sr_ethernet_hdr*);
void print_arp(struct sr_arphdr*);
void print_addr(char*);
void print_ip(uint32_t);
struct arp_entry* updateArpCache(uint32_t, unsigned char*);
void sendBufferPackets(struct arp_entry*, unsigned char*);
struct arp_entry* getArpEntry(uint32_t);

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */
  	
  	// LOAD ROUTING TABLE
  	// changing method of accesing routing table
  	routingTable = sr->routing_table;
  /*
  	int rc = sr_load_rt(routingTable, "rtable");
  	if (rc) {
      	perror("Error loading routing table.\n");
      	exit(1);
    }
  */
  	// LOAD INTERFACE LIST
    //interfaceList = sr->if_list;
  	//assert(interfaceList);
  
  	// LOAD ARP TABLE
    arp_entry_head = (struct arp_entry*) malloc(sizeof(struct arp_entry));
    memset(arp_entry_head, 0, sizeof(struct arp_entry));

} /* -- sr_init -- */



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

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
  
  	//retrieve info about interface
  	struct sr_if* inter = sr_get_interface(sr, interface);
  
  	// Cast packet as ethernet header to access header fields
  	struct sr_ethernet_hdr *eth_hdr = NULL;
  	eth_hdr = (struct sr_ethernet_hdr *) packet;
  
  	//printing packet's ethernet header
  	printf("packet ethernet Frame:\n");
  	print_ethFrame(eth_hdr);
    
  	// Get packet type ID
  	uint16_t packetType = eth_hdr->ether_type;
  
  	////////////////////////////
  	// * * * ARP PACKET * * * //
   	////////////////////////////
    if (ntohs(packetType) == ETHERTYPE_ARP) {
		printf("ARP header found\n");
      
        struct sr_arphdr *arphdr = (struct sr_arphdr*) (packet + sizeof(struct sr_ethernet_hdr));
        
        print_arp(arphdr);
        assert(ntohs(arphdr->ar_hrd) == 1);
        assert(ntohs(arphdr->ar_pro) == 0x0800);
        assert(arphdr->ar_hln == 6);
        assert(arphdr->ar_pln == 4);

        unsigned short opCode = ntohs(arphdr->ar_op);

        if (opCode == 1) { //this is request ARP
          printf("obtained REQUEST ARP\n");
          
          ////// changing same packet as a reply ARP
          
          // setting reply ethernet header
          memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost,sizeof(uint8_t)*ETHER_ADDR_LEN);
          memcpy(eth_hdr->ether_shost, inter->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
          
          //printing reply ethernet
          printf("reply packet header:\n");
          print_ethFrame(eth_hdr);
          
          // setting the ARP header for reply
          arphdr->ar_op = htons(2);
          memcpy(arphdr->ar_tha, arphdr->ar_sha, sizeof(unsigned char)*6);
          memcpy(&(arphdr->ar_tip), &(arphdr->ar_sip), sizeof(uint32_t));
          memcpy(arphdr->ar_sha, inter->addr, sizeof(unsigned char)*6);
          memcpy(&(arphdr->ar_sip), &(inter->ip),   sizeof(uint32_t));
 
          // printing reply ARP
          print_arp(arphdr);
          
          int rc = sr_send_packet(sr, (uint8_t*) eth_hdr, len, interface);
          printf("sending ARP reply\n");
          assert(rc == 0);
            
        } else if (opCode == 2) { // this is reply ARP
          	printf("obtained REPLY ARP\n");
          	// When router forwards a packet to the nexthop but doesn’t know the nexthop’s Ethernet (MAC) address, it sends an ARP request 
          	// Parse the returned ARP reply to get sender's IP and MAC.  Add IP:MAC mapping to ARP cache.
          	// any packets saved in buffer waiting for the MAC address are sent
            struct arp_entry* arpEntry;
            arpEntry = updateArpCache(arphdr->ar_sip, arphdr->ar_sha);
			arpEntry->macNotNull = 1;
            //sendBufferPackets(arpEntry, arphdr->ar_sha);
            
            struct packet_buffer* buffer;
            buffer = arpEntry->buffer;
            unsigned char* addr = arpEntry->addr;   
            
            // sending all waiting packets
            while (buffer != NULL) {

                struct sr_arphdr *arp_rep = (struct sr_arphdr*) (buffer + sizeof(struct sr_ethernet_hdr));
 
                memcpy(arp_rep->ar_tha, addr, sizeof(unsigned char)*6);
                rc = sr_send_packet(sr,buffer->packet, buffer->len, buffer->interface);
                printf("sending IP after ARP reply\n");
                assert(rc == 0);
                struct packet_buffer* temp = buffer;
                buffer = buffer->next;
                free(temp);
            }

            arpEntry->buffer = NULL;



        } else {
            printf("error, no valid opCode in ARP\n");
            exit(1);
        }
	}
  	///////////////////////////
  	// * * * IP PACKET * * * //
   	///////////////////////////
  	else if (ntohs(packetType) == ETHERTYPE_IP) { // this is an IP packet
    
        printf("IP packet found\n");
    	// Move pointer past ethernet header & cast to IP header
      	struct ip *iphdr = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));  
      
      	// * * IP PACKET PROCESSING (project2 slides, slide 7) * * 
        // Verify IP version is '4'
      	//printf("ip header - verstion: %d\n",iphdr->ip_v);
        assert(iphdr->ip_v == 4);
      
      	// NOTE: Checksum ver & TTL decrementation not required in this project but it would normally happen here
       
      	// Use packet's destination address to look up routing table, find a matching entry in the table
  		uint32_t destination = iphdr->ip_dst.s_addr;
      	
      	struct sr_rt *thisEntry = routingTable;
      	struct sr_rt *matchingEntry = NULL;
      	int longestMask = 0;
      	      
      	// Examine all routing table entries to find the match with the longest mask
      	while (thisEntry) {
          	uint32_t mask = thisEntry->mask.s_addr;
          	uint32_t network = thisEntry->dest.s_addr;
          	uint32_t destAndMask = (destination & mask);
          	uint32_t networkAndMask = (network & mask);
          
          	if ((destAndMask == networkAndMask) && (mask >= longestMask)) { // Matching entry found     	
                matchingEntry = thisEntry;
                longestMask = mask;
            }

			thisEntry = thisEntry->next;
        }


  		// Determine IP, MAC address, and interface we must send packet to
  		uint32_t nexthopIp;
  		char iface[sr_IFACE_NAMELEN];
  		struct arp_entry *arpRecord = NULL; 
  
		if (matchingEntry->gw.s_addr == 0) { // Destination is a local address, packet goes to destination
          	nexthopIp = destination;
        }
        else { // Destination is NOT a local address, packet goes to nexthop
          	
            nexthopIp = matchingEntry->gw.s_addr;  
        }

        strcpy(iface, matchingEntry->interface);


  		arpRecord = getArpEntry(nexthopIp);
  	
  		// Send packet if an ARP record was found, otherwise enqueue it and request ARP info
  		if (arpRecord) {

            printf("arp record found\n");
            // Update ethernet header and send the packet to the IP:MAC given
        	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(uint8_t)*ETHER_ADDR_LEN); 
          	memcpy(eth_hdr->ether_dhost, arpRecord->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
            
            print_ethFrame(eth_hdr);
          	rc = sr_send_packet(sr, packet, len, iface);
            printf("sending IP packet\n");
            assert(rc == 0);  
        } else {

     		// Create ARP cache entry - will have null MAC address until ARP reply is received
          	arpRecord = updateArpCache(nexthopIp, NULL);
          	
          	// Add this packet to the queue that will be sent to destination device after ARP reply is received.
          	// Must copy local data to queued packet struct so it can exist outside this scope...
          	struct packet_buffer* queuedPacket = (struct packet_buffer *) malloc(sizeof(struct packet_buffer));
          	queuedPacket->packet = (uint8_t *) malloc(sizeof(uint8_t) * len);
          	memcpy(queuedPacket->packet, packet, len);
  			queuedPacket->len = len;
  			strcpy(queuedPacket->interface, iface);
    		queuedPacket->next = NULL;
          	
          	if (!arpRecord->buffer) {
            	// Packet buffer queue is currently EMPTY -- this packet will be the first in queue
              	arpRecord->buffer = queuedPacket;
            } else {
              	// Packet buffer queue is not empty -- add this packet to the end of queue
              	struct packet_buffer* queue = arpRecord->buffer;
              	while (queue->next) {
                  	queue = queue->next;
                }
              	queue->next = queuedPacket;
            }

            size_t size = (sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
            uint8_t *request = (uint8_t*) malloc(size);
            memset(request, 0, size);

            struct sr_ethernet_hdr *eth_request = (struct sr_ethernet_hdr*) request;
            unsigned char broad[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            memcpy(eth_request->ether_dhost, broad, ETHER_ADDR_LEN);

            struct sr_if* inf = sr_get_interface(sr, iface);
            memcpy(eth_request->ether_shost, inf->addr, ETHER_ADDR_LEN);

            eth_request->ether_type = htons(0x0806);

            printf("sending request arp packet:\n");
            print_ethFrame(eth_request);

            struct sr_arphdr *arp_request = (struct sr_arphdr*) (request + (sizeof(struct sr_ethernet_hdr)));

            arp_request->ar_hrd = htons(1);
            arp_request->ar_pro = htons(0x0800);
            arp_request->ar_hln = 6;
            arp_request->ar_pln = 4;
            memcpy(arp_request->ar_sha, inf->addr,ETHER_ADDR_LEN);
            arp_request->ar_sip = inf->ip;
            //memcpy(arp_request->ar_tha, ,ETHER_ADD_LEN); //not necessary
            arp_request->ar_tip = nexthopIp;
            arp_request->ar_op = htons(1);

            print_arp(arp_request);

            int rc = sr_send_packet(sr, request, size, inf->name);
            assert(rc == 0);

        }
    
	} else {
      	// THIS IS NOT AN IP OR ARP PACKET, WE SHOULD NEVER GET HERE
      	assert(0);
    }

    printf("---------------------------- END OF PACKET HANDLING -----------------------------------------------\n");
}/* end sr_ForwardPacket */


/* Method: getArpEntry()
 * 
 * Takes as parameter an IP address (sourced from a packet's destination address) and 
 * returns the a pointer to the ARP cache entry detailing the IP:MAC mapping of that address.
 * 
 * If IP address is not found in ARP cache, returns NULL
 * 
 */
struct arp_entry* getArpEntry(uint32_t ipAddr) {
	struct arp_entry *entry = arp_entry_head;
  	
  	while (entry->next) {
        entry = entry->next;
      	if (ipAddr == entry->ip.s_addr && entry->macNotNull) {
        	// Parameter IP address found in ARP cache, return ARP table entry
          	return entry;
        }
    }
  	assert(entry->next == NULL);
  	return NULL;
}

/* Method: updateArpCache
 * 
 * Update the ARP cache with the IP:MAC mapping in args
 * 
 * NOTE: The structs malloc'd here will never have free() called on them - this
 * is due to them being used for the remainder of the program's execution, which 
 * is killed by ctrl+c rather than by a clean shutdown routine.
 */
struct arp_entry* updateArpCache(uint32_t ipAddr, unsigned char* macAddr) {

    // Check ARP cache to see if record exists for this ip address
    // If record exists: update it with <macAddr>
    // If no record: add it to ARP cache

    printf("update arp cache\n");

    struct arp_entry *ite = arp_entry_head;

    while (ite->next != NULL) {

        printf("---1\n");
        struct arp_entry *cur = ite->next;

        if (memcmp(&(cur->ip.s_addr), &ipAddr, sizeof(uint32_t)) == 0) {

            printf("ip address found in chache\n");
            // IP address found in ARP cache, update ARP cache's IP:MAC mapping and return
            if (macAddr != NULL) {
                memcpy(cur->addr, macAddr, sizeof(unsigned char)*ETHER_ADDR_LEN);
                cur->macNotNull = 1;
            }
            return cur;
        }

        ite = ite->next;
    }

    printf("arp not found\n");

    // No record for this IP address exists in ARP cache - add one to the ***start*** of the cache
    struct arp_entry *newArp = (struct arp_entry*) malloc(sizeof(struct arp_entry));
    memset(newArp, 0, sizeof(struct arp_entry));
    
    if (macAddr != NULL) {
        memcpy(newArp->addr, macAddr, ETHER_ADDR_LEN);
        newArp->macNotNull = 1;
    } else {
        newArp->macNotNull = 0;
    }
    
    memcpy(&(newArp->ip.s_addr), &ipAddr, sizeof(uint32_t));
    newArp->next = arp_entry_head->next;
    arp_entry_head->next = newArp;
    printf("arp cache end\n");
    return newArp;
}

void print_ethFrame(struct sr_ethernet_hdr *ethFrame) {

    printf("Frame {\n");
    printf("\tdest: %X:%X:%X:%X:%X:%X\n",
            ethFrame->ether_dhost[0],
            ethFrame->ether_dhost[1],
            ethFrame->ether_dhost[2],
            ethFrame->ether_dhost[3],
            ethFrame->ether_dhost[4],
            ethFrame->ether_dhost[5]);

    printf("\tsrc:  %X:%X:%X:%X:%X:%X\n",
            ethFrame->ether_shost[0],
            ethFrame->ether_shost[1],
            ethFrame->ether_shost[2],
            ethFrame->ether_shost[3],
            ethFrame->ether_shost[4],
            ethFrame->ether_shost[5]);

    printf("\ttype: %X\n", ntohs(ethFrame->ether_type));
    printf("}\n");

}
            
void print_arp(struct sr_arphdr* arp) {

    int i;

    printf("ARP {\n");
    printf("\thard: %d\n\
        Prot: %d\n\
        Hlen: %d\n\
        Plen: %d\n\
        op  : %d\n\
        sha : ",
        ntohs(arp->ar_hrd),
        ntohs(arp->ar_pro),
        arp->ar_hln,
        arp->ar_pln,
        ntohs(arp->ar_op));

    for(i = 0; i < 6;i++) {
        printf("%X:",arp->ar_sha[i]);
    }
    printf("\n");

    printf("\tsip : %s\n",inet_ntoa((struct in_addr) {arp->ar_sip}));

    printf("\ttha : ");
    for (i=0;i<6;i++) {
        printf("%X:",arp->ar_tha[i]);
    }
    printf("\n");
    printf("\ttip : %s\n",inet_ntoa((struct in_addr) {arp->ar_tip}));
    printf("}\n");

}

void print_addr(char* addr) {
    printf("%X:%X:%X:%X:%X:%X\n",
            addr[0],
            addr[1],
            addr[2],
            addr[3],
            addr[4],
            addr[5]);


}

void print_ip(uint32_t ip) {
    printf("ip: %s\n", inet_ntoa((struct in_addr) {ip}));
}



