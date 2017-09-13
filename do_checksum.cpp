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
#include "ProbeRoute.hpp"

#define CKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

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

int do_checksum(u_char *buf, int protocol, int len) throw(ProbeException)
/* len = protocol header length + payload length */
{
    struct ip *ip;
    int iplen, sum = 0;
    std::stringstream msg;

    if (len == 0 && protocol != IPPROTO_IP) {
        throw ProbeException("header length can't be zero", MSG);
    }

    ip = (struct ip *)buf;
    if (ip->ip_v != 4) {
        msg << "Unsupported IP protocol: " << ip->ip_v;
        throw ProbeException(msg.str());
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
        msg << "Unsupported protocol: " << protocol;
        throw ProbeException(msg.str());
    }
    }

    return 0;
}


