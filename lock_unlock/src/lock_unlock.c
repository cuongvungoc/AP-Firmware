#include "dns_parser_daemon.h"
#include <syslog.h>

// Function for multithreading dns parser
int main()
{
    eth_header *eth_hdr;
    ip_header *ip_hdr;
    udp_header *udp_hdr;
    dns_header *dns_hdr;
    dns_question *dns_quest;
    unsigned char *payload;
    unsigned char *name;
    unsigned char *qname;
    int qname_len;
    int i = 0, j = 0;
    // Convert IP to dotted decimal string
    long *p;
    struct sockaddr_in a;

    unsigned char buffer[BUF_SIZE];
    struct dns_record_t answer[RECORD_NUM]; // Record from dns server
    struct white_list_t *wlist = (struct white_list_t *)malloc(WLIST_LEN * sizeof(struct white_list_t *));
    // struct white_list_t *wlist;
    wlist->len = 0;

    //  For get host by name
    struct hostent *he;
    struct in_addr **addr_list;
    char default_ip_des[CMD_SIZE] = "iptables -I white_list 1 -d ";
    char default_ip_src[CMD_SIZE] = "iptables -I white_list 1 -s ";
    if (NULL == (he = gethostbyname(URL)))
    {
        syslog(LOG_WARNING,"Cannot get host by name\n");
        return 1;
    }
    syslog(LOG_WARNING,"[%s:%d][cuongvn]\n",__func__,__LINE__);
    addr_list = (struct in_addr **) he->h_addr_list;

    add_to_whitelist(wlist, inet_ntoa(*addr_list[0]));

    // Open a raw socket, receive
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    // Receive all incoming packet
    int on = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
    {
        perror("setsockopt");
        exit(1);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(NET_INTERFACE); // Read all message from net interface
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        perror("bind");
        exit(1);
    }
    
    while (1)
    {
        // Set buffer for reading dns response message
        memset(buffer, 0, sizeof(buffer));
        int len = recv(sockfd, buffer, sizeof(buffer), 0);
        if (len < 0)
        {
            perror("recv");
            exit(1);
        }

        eth_hdr = (eth_header *)&buffer;
        ip_hdr = (ip_header *)&buffer[sizeof(eth_header)];

        // Check IP Protocol : 17 - UDP
        if (ip_hdr->ip_proto == UDP_PROTO)
        {
            // Read UDP header
            udp_hdr = (udp_header *)&buffer[sizeof(ip_header) + sizeof(eth_header)];

            // Check UDP source port: 53 - DNS
            if (ntohs(udp_hdr->src_port) == DNS_PORT)
            {
                // Read DNS header
                dns_hdr = (dns_header *)&buffer[sizeof(ip_header) + sizeof(eth_header) + sizeof(udp_header)];

                // Read name (URL)
                qname = (unsigned char *)&buffer[sizeof(ip_header) + sizeof(eth_header) + sizeof(udp_header) + sizeof(dns_header)];

                // Find name length
                qname_len = find_qname_len(qname);

                name = (unsigned char *)malloc(qname_len * sizeof(unsigned char));
                memcpy(name, qname, qname_len);

                // If name equal to url -> get IP from dns answer
                if (0 == compare_name_to_url(name, URL, qname_len))
                {
                    dns_quest = (dns_question *)&qname[qname_len];
                    payload = (unsigned char *)&qname[qname_len + sizeof(dns_question)];

                    // Read Answer
                    int payload_ptr = 0;
                    for (i = 0; i < ntohs(dns_hdr->ancount); i++)
                    {
                        answer[i].name = (unsigned char *)malloc(qname_len * sizeof(unsigned char));
                        memcpy(answer[i].name, qname, qname_len);
                        payload_ptr += sizeof(unsigned short); // DNS name pointer C00C
                        answer[i].resource = (struct dns_resource_record_t *)&payload[payload_ptr];
                        payload_ptr += sizeof(struct dns_resource_record_t);

                        if (DNS_RECORD_TYPE_A == ntohs(answer[i].resource->type))
                        {
                            answer[i].rdata = (unsigned char *)malloc(ntohs(answer[i].resource->length) * sizeof(unsigned char));
                            for (j = 0; j < ntohs(answer[i].resource->length); j++)
                            {
                                answer[i].rdata[j] = payload[payload_ptr + j];
                            }
                            
                            // // Convert IP to dotted decimal string
                            p = (long *)answer[i].rdata;
                            a.sin_addr.s_addr = (*p);
                            add_to_whitelist(wlist, inet_ntoa(a.sin_addr));

                            for (i = 0; i < ntohs(dns_hdr->ancount); i++)
                            {
                                free(answer[i].rdata);
                                free(answer[i].name);
                            }
                        }
                    }      
                }
                free(name);
            }
        }  
    }
    free(wlist);
    sleep(1);
    return 0;
}