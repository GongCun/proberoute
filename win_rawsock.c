#include <w32api/winsock2.h>
#include <w32api/windows.h>
#include <w32api/mstcpip.h>
#include <stdio.h>

#define DEFAULT_NAMELEN 512

int main(int argc, char **argv)
{
    int ret;
    WSADATA wsaData;
    SOCKET rawfd = INVALID_SOCKET;
    DWORD dwBufferLen[10];
    DWORD Optval = 1;
    DWORD dwBytesReturned = 0;

    struct in_addr addr;
    struct sockaddr_in LocalAddr, RemoteAddr;
    int addrLen = sizeof(struct sockaddr_in);
    int in = 0, i = 0;
    struct hostent *local;
    char HostName[DEFAULT_NAMELEN];
    
    


    /* Initialize Winsock */
    ret = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (ret != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", ret);
        return -1;
    }

    /* Create Raw Socket */
    rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (rawfd == INVALID_SOCKET || rawfd == SOCKET_ERROR) {
        fprintf(stderr, "socket failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    /* Get Local HostName */
    ZeroMemory(HostName, sizeof(HostName));
    if ((gethostname(HostName, sizeof(HostName))) == SOCKET_ERROR) {
        fprintf(stderr, "gethostname failed with error: %d", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    /* Get Local IP Address */
    local = gethostbyname(HostName);
    if (local == NULL) {
        fprintf(stderr, "gethostname failed with error: %d", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    while (local->h_addr_list[i] != 0) {
        addr.s_addr = *(u_long *)local->h_addr_list[i++];
        printf("IP Address #%d: %s\n", i, inet_ntoa(addr));
    }

    printf("\nChoose the adapter#: ");
    scanf("%d", &in);
    ZeroMemory(&LocalAddr, sizeof(LocalAddr));
    memcpy(&LocalAddr.sin_addr.S_un.S_addr,
           local->h_addr_list[in-1],
           sizeof(LocalAddr.sin_addr.S_un.S_addr));
    LocalAddr.sin_family = AF_INET;
    LocalAddr.sin_port = 0;

    /* Bind Local Address */
    if ((bind(rawfd, (struct sockaddr *)&LocalAddr, sizeof(LocalAddr))) == SOCKET_ERROR) {
        fprintf(stderr, "bind failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    /* Set the SIO_RCVALL ioctl */
    if ((WSAIoctl(rawfd, SIO_RCVALL, &Optval, sizeof(Optval),
                  &dwBufferLen, sizeof(dwBufferLen),
                  &dwBytesReturned, NULL, NULL)) == SOCKET_ERROR) {
        fprintf(stderr, "WSAIoctl failed with error: %d\n", WSAGetLastError());
        return -1;
    }

    return rawfd;
}
