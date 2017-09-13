#include "tcptraceroute.h"

uint16_t checksum(uint16_t * addr, int len)
{
        int nleft = len;
        uint16_t *w = addr;
        uint16_t answer = 0;
        uint32_t sum = 0;

        while (nleft > 1) {
                sum += *w++;
                nleft -= 2;
        }
        
        if (nleft == 1) {
                *((unsigned char *)&answer) = *((unsigned char *)w); /* only 1 byte */
                sum += answer;
        }
        
                                /* Fold 32-bit sum to 16 bits */
        while (sum >> 16)
                sum = (sum >> 16) + (sum & 0xffff); /* hi 16 + low 16 */
        
        answer = ~sum;          /* truncate to 16 bit */
        return answer;
}


/*
 *  The following code comes from:
 *
 *  libnet
 *  libnet_checksum.c - checksum routines
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 */

static uint32_t in_checksum(uint16_t * addr, int len)
{
        uint32_t sum = 0;

        while (len > 1) {
                sum += *addr++;
                len -= 2;
        }

        if (len == 1)
                sum += *(uint16_t *)addr;

        return sum;
}

int do_checksum(u_char *buf, int protocol, int len)
        /* len = protocol header length + payload length */
{
        struct ip *ip;
        int iplen, sum = 0;

        if (len == 0 && protocol != IPPROTO_IP) {
                fprintf(stderr, "header length can't be zero");
                return -1;
        }

        ip = (struct ip *)buf;
        if (ip->ip_v != 4) {
                fprintf(stderr, "Unsupported IP protocol: %d", ip->ip_v);
                return -1;
        }
        iplen = ip->ip_hl << 2;

        switch (protocol) {
                case IPPROTO_TCP:
                {
                        struct tcphdr *tcp = (struct tcphdr *)(buf + iplen);
                        tcp->th_sum = 0;
                        sum = in_checksum((uint16_t *)&ip->ip_src, 8);
                        sum += ntohs(IPPROTO_TCP+len);
                        sum += in_checksum((uint16_t *)tcp, len);
                        tcp->th_sum = CKSUM_CARRY(sum);
                        break;
                }
                case IPPROTO_UDP:
                {
                        struct udphdr *udp = (struct udphdr *)(buf + iplen);
                        udp->uh_sum = 0;
                        sum = in_checksum((uint16_t *)&ip->ip_src, 8);
                        sum += ntohs(IPPROTO_UDP+len);
                        sum += in_checksum((uint16_t *)udp, len);
                        udp->uh_sum = CKSUM_CARRY(sum);
                        break;
                }
                case IPPROTO_ICMP:
                {
                        struct icmp *icmp = (struct icmp *)(buf + iplen);
                        icmp->icmp_cksum = 0;
                        sum = in_checksum((uint16_t *)icmp, len);
                        icmp->icmp_cksum = CKSUM_CARRY(sum);
                        break;
                }
                case IPPROTO_IP:
                {
                        ip->ip_sum = 0;
                        sum = in_checksum((uint16_t *)ip, iplen);
                        ip->ip_sum = CKSUM_CARRY(sum);
                        break;
                }
                default:
                {
                        fprintf(stderr, "Unsupported protocol: %d", protocol);
                        return -1;
                }
        }
#ifdef _DEBUG
        printf("\nProtocol: %d: %x\n", protocol, CKSUM_CARRY(sum));
#endif
        return 0;
}


