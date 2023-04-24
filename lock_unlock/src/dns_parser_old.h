#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <netdb.h>

#define BUF_SIZE 65536
#define RECORD_NUM 32
#define NET_INTERFACE "ens33"
#define DNS_RECORD_TYPE_A 1
#define DNS_RECORD_TYPE_CNAME 5
#define CMD_SIZE 50
#define OPTION_SIZE 10
#define IP_LEN 20
#define WLIST_LEN 20
#define UDP_PROTO 17
#define DNS_PORT 53
#define ZERO_CHAR 48
#define UNLOCK_STATE 0
#define LOCK_STATE 1
#define URL "hust.edu.vn"
#define LOCK "lock"
#define UNLOCK "unlock"
#define NULL_SAVE " > /dev/null 2>&1"

extern int state_alarm;
extern int nslookup_trigger;
extern pthread_mutex_t mutex;

struct white_list_t
{
    int len;
    char ip_list[WLIST_LEN][IP_LEN];
};

typedef struct eth_header_t
{
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_src[ETH_ALEN];
    unsigned short h_proto;
} eth_header; // eth_hdr

typedef struct ip_header_t
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hdr_len : 4;
    unsigned int version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version : 4;
    unsigned int ip_hdr_len : 4;
#endif
    unsigned char dif_ser; // Different service
    unsigned short total_len;
    unsigned short id;
    unsigned short frag_off; // Fragment offset
    unsigned char ttl;       // Time to live
    unsigned char ip_proto;  // Protocol
    unsigned short checksum;
    unsigned int scr_addr;
    unsigned int dest_addr;
} ip_header; // ip_hdr

typedef struct udp_header_t
{
    unsigned short src_port;
    unsigned short dest_port;
    unsigned short len;
    unsigned short checksum;
} udp_header; // udp_hdr

typedef struct dns_header_t
{
    unsigned short id; // id number
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char rd : 1;     // recursion desired
    unsigned char tc : 1;     // truncation
    unsigned char aa : 1;     // authoritative answer
    unsigned char opcode : 4; // kind of query
    unsigned char qr : 1;     // query/response flags
    unsigned char rcode : 4;  // response code
    unsigned char cd : 1;     // checking disable flag
    unsigned char ad : 1;     // authenticated data flag
    unsigned char z : 1;      // reverse - must be zero
    unsigned char ra : 1;     // recursion available
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char qr : 1;     // query/response flags
    unsigned char opcode : 4; // kind of query
    unsigned char aa : 1;     // authoritative answer
    unsigned char tc : 1;     // truncation
    unsigned char rd : 1;     // recursion desired
    unsigned char ra : 1;     // recursion available
    unsigned char z : 1;      // reverse - must be zero
    unsigned char ad : 1;     // authenticated data flag
    unsigned char cd : 1;     // checking disable flag
    unsigned char rcode : 4;  // response code
#endif
    unsigned short qdcount; // number of question
    unsigned short ancount; // number of answer records
    unsigned short nscount; // number of authority records
    unsigned short arcount; // number of additional records
} dns_header;               // dns_hdr

typedef struct dns_question_t
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short qclass;
    unsigned short qtype;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned short qtype;
    unsigned short qclass;
#endif
} dns_question; // dns_question

#pragma pack(push, 1)
struct dns_resource_record_t
{
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short length;
}; // dns_resource
#pragma pack(pop)

struct dns_record_t
{
    unsigned char *name;
    struct dns_resource_record_t *resource;
    unsigned char *rdata;
}; // dns_record

struct dns_query_t
{
    unsigned char *name;
    struct question_t *quest;
}; // dns_query

// state_alarm, 0 - unlock, 1 - lock
void set_state_alarm(int state_val);
int get_state_alarm();

// Compare name to url (only 1 url is accepted)
int compare_name_to_url(unsigned char *name, char *url, int len);

// Check is IP exist in white list; return 1 - exist, 0 not exist
int is_exist(struct white_list_t *wlist, char *ip);

// change url to dns name format, example: google.com -> 6google3com
void change_to_dns_name_format(char *dns, char *host);

// Function for multithreading dns parser
void *dns_parser();

// Find domain name length in query section
int find_qname_len(unsigned char buffer[]);

#endif /* DNS_PARSER_H*/