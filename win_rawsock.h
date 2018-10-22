#ifndef _WIN_RAWSOCK_H
#define _WIN_RAWSOCK_H

#include <w32api/winsock2.h>
#include <w32api/windows.h>
#include <w32api/mstcpip.h>
#include <stdio.h>

#ifndef offsetof
#define offsetof(type, f) ((size_t) ((char *)&((type *)0)->f - (char *)(type *)0))
#endif

typedef struct ip_hdr {
    unsigned char  ip_header_len:4;   // 4-bit header length (in 32-bit words)
                                      // normally = 5 (Means 20 Bytes may be 24 also)
    unsigned char  ip_version :4;     // 4-bit IPv4 version
    unsigned char  ip_tos;            // IP type of service
    unsigned short ip_total_length;   // Total length
    unsigned short ip_id;             // Unique identifier

    unsigned char  ip_frag_offset :5; // Fragment offset field

    unsigned char  ip_more_fragment :1;
    unsigned char  ip_dont_fragment :1;
    unsigned char  ip_reserved_zero :1;

    unsigned char  ip_frag_offset1;   //fragment offset

    unsigned char  ip_ttl;            // Time to live
    unsigned char  ip_protocol;       // Protocol(TCP,UDP etc)
    unsigned short ip_checksum;       // IP checksum
    struct in_addr ip_src, ip_dst;    // Source address
} IPV4_HDR;

int win_rawsock(const struct sockaddr *addr, int addrlen);
/* int win_recvfrom(SOCKET s, char *buf, int len); */
int win_recvfrom(SOCKET s, char *buf, int len, const struct sockaddr *local);
#endif
