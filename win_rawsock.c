#include "win_rawsock.h"

int win_rawsock(const struct sockaddr *addr, int addrlen)
{
    int ret;
    WSADATA wsaData;
    SOCKET rawfd = INVALID_SOCKET;
    DWORD Optval = 1;
    DWORD dwBytesReturned = 0;

    /* Initialize Winsock */
    ret = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (ret != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", ret);
        return -1;
    }

    /* Create Raw Socket */
    /* rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_IP); */
    rawfd = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP,
                      NULL, 0, WSA_FLAG_OVERLAPPED);

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

    if ((WSAIoctl(rawfd,                     /* descriptor identifying a socket */
                  SIO_RCVALL,                /* dwIoControlCode */
                  &Optval,                   /* lpvInBuffer */
                  sizeof(Optval),            /* cbInBuffer */
                  NULL,                      /* lpvOutBuffer output buffer */
                  0,                         /* size of output buffer */
                  (LPDWORD)&dwBytesReturned, /* number of bytes returned */
                  NULL,                      /* OVERLAPPED structure */
                  NULL                       /* completion routine */
         )) == SOCKET_ERROR) {
        fprintf(stderr, "WSAIoctl failed with error: %d\n", WSAGetLastError());
        return -1;
    }

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
    WSABUF DataBuf;
    WSAEVENT EventArray[WSA_MAXIMUM_WAIT_EVENTS];
    WSAOVERLAPPED RecvOverlapped;
    DWORD EventTotal = 0, RecvBytes = 0, Flags = 0;
    DWORD Index;
    

    /* Crete event, build OVERLAPPED structure. */
    ZeroMemory(&RecvOverlapped, sizeof(RecvOverlapped));
    EventArray[EventTotal] = RecvOverlapped.hEvent = WSACreateEvent();
    if (EventArray[EventTotal] == WSA_INVALID_EVENT) {
        fprintf(stderr, "WSACreateEvent() failed with error %d\n", WSAGetLastError());
        return -1;
    }
    DataBuf.buf = buf;
    DataBuf.len = len;
    EventTotal++;
    

    do {
        /* n = recvfrom(s, buf, len, 0, (struct sockaddr *)&addr, &addrlen); */
        n = WSARecvFrom(s, &DataBuf, 1,
                        &RecvBytes, &Flags,
                        (struct sockaddr *)&addr, &addrlen,
                        &RecvOverlapped, NULL);
        
        if (n == SOCKET_ERROR) {
            if (WSAGetLastError() != WSA_IO_PENDING) {
                fprintf(stderr, "WSARecvFrom failed with error: %d\n", WSAGetLastError());
                return -1;
            }
            else {
                n = WSAWaitForMultipleEvents(EventTotal, &RecvOverlapped.hEvent, TRUE, INFINITE, TRUE);
                if (n == WSA_WAIT_FAILED) {
                    fprintf(stderr, "WSAWaitForMultipleEvents failed with error: %d\n", WSAGetLastError());
                    return -1;
                }
                Index = n;

                n = WSAGetOverlappedResult(s, &RecvOverlapped, &RecvBytes, FALSE, &Flags);
                if (n == FALSE) {
                    fprintf(stderr, "WSAGetOverlappedResult failed with error: %d\n", WSAGetLastError());
                    return -1;
                }
            }
        }
        
        WSAResetEvent(EventArray[Index - WSA_WAIT_EVENT_0]);
        
        Flags = 0;
        ZeroMemory(&RecvOverlapped, sizeof(RecvOverlapped));
        RecvOverlapped.hEvent = EventArray[0];

    } while (RecvBytes > 0 && SockComp((struct sockaddr *)&addr, (struct sockaddr *)local));
    
    
    /* if (RecvBytes < 0) */
    /*     fprintf(stderr, "recvfrom(WIN) failed with error: %d\n", WSAGetLastError()); */
    /* else */
    /*     fprintf(stderr, "win from %s, length = %d\n", inet_ntoa(addr.sin_addr), RecvBytes); */
    return RecvBytes;

}
