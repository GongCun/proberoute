#include "win_rawsock.h"

int win_rawsock(const struct sockaddr *addr, int addrlen)
{
    int ret;
    WSADATA wsaData;
    SOCKET rawfd = INVALID_SOCKET;
    /* DWORD dwBufferLen[10]; */
    DWORD Optval = 1;
    DWORD dwBytesReturned = 0;

    /* Initialize Winsock */
    ret = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (ret != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", ret);
        return -1;
    }

    /* Create Raw Socket */
    rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    /* rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); */
    if (rawfd == INVALID_SOCKET || rawfd == SOCKET_ERROR) {
        fprintf(stderr, "socket failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    /* Bind Local Interface Address */
    if (bind(rawfd, addr, addrlen) == SOCKET_ERROR) {
        fprintf(stderr, "bind failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    /* Set the SIO_RCVALL ioctl */
    if ((WSAIoctl(rawfd, SIO_RCVALL, &Optval, sizeof(Optval),
                  /* &dwBufferLen, sizeof(dwBufferLen), */
                  NULL, 0,
                  (LPDWORD)&dwBytesReturned, /* A pointer to actual number of
                                              * bytes of output. */
                  NULL, NULL)) == SOCKET_ERROR) {
        fprintf(stderr, "WSAIoctl failed with error: %d\n", WSAGetLastError());
        return -1;
    }

    /*
    struct sockaddr_in RemoteAddr;
    int RemoteAddrlen = sizeof(RemoteAddr);
    char buf[65535];

    ret = recvfrom(rawfd, buf, sizeof(buf), 0, (struct sockaddr *)&RemoteAddr, &RemoteAddrlen);
    if (ret < 0) {
        fprintf(stderr, "recvfrom(WIN) failed with error: %d\n", WSAGetLastError());
        return -1;
    }

    if (ret >= 0) {
        fprintf(stderr, "from %s, length = %d\n", inet_ntoa(RemoteAddr.sin_addr), ret);
        return -1;
    }
    */

    /* char buf[65535]; */
    /* win_recvfrom(rawfd, buf, sizeof(buf)); */
    /* printf("Dunc() rawfd = %LLD\n", rawfd); */

    return rawfd;
}

/* In Winsock applications, a socket descriptor is not a file descriptor and
 * must be used with the Winsock functions. */

static int SockComp(const struct sockaddr *addr1, const struct sockaddr *addr2)
{
    struct sockaddr_in *inaddr1 = (struct sockaddr_in *)addr1;
    struct sockaddr_in *inaddr2 = (struct sockaddr_in *)addr2;

    return (inaddr1->sin_addr.s_addr == inaddr2->sin_addr.s_addr);
}

int win_recvfrom(SOCKET s, char *buf, int len, const struct sockaddr *local)
{
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);
    int n;
    IPV4_HDR *iphdr;

    /* struct sockaddr_in *p = (struct sockaddr_in *)local; */
    /* fprintf(stderr, ">> local address %s\n", inet_ntoa(p->sin_addr)); */
    do {
        n = recvfrom(s, buf, len, 0, (struct sockaddr *)&addr, &addrlen);
        /* n = recvfrom(s, buf, len, 0, NULL, NULL); */
        /* fprintf(stderr, "win from %s, length = %d\n", inet_ntoa(addr.sin_addr), n); */
    } while (n > 0 && SockComp((struct sockaddr *)&addr, (struct sockaddr *)local));
    
    if (n < 0)
        fprintf(stderr, "recvfrom(WIN) failed with error: %d\n", WSAGetLastError());
    /* else */
        /* fprintf(stderr, "win from %s, length = %d\n", inet_ntoa(addr.sin_addr), n); */
    return n;

#if 0
    for (;;) {
    n = recvfrom(s, buf, len, 0, NULL, NULL);
    if (n < 0) {
        fprintf(stderr, "recvfrom(WIN) failed with error: %d\n", WSAGetLastError());
        exit(-1);
    }

    /* if (n >= 0) */
        /* fprintf(stderr, "from %s, length = %d\n", inet_ntoa(addr.sin_addr), n); */
        /* fprintf(stderr, "length = %d\n", n); */

    iphdr = (IPV4_HDR *)buf;
    if ((uint8_t)iphdr->ip_protocol == 1) {
    printf("win from: %s\n", inet_ntoa(iphdr->ip_src));
    printf("win to: %s\n", inet_ntoa(iphdr->ip_dst));
    printf("win protocol offset: %ld\n\n", offsetof(IPV4_HDR, ip_protocol));
    }
    }
#endif
}
