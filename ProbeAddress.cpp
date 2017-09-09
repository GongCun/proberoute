#include "ProbeRoute.hpp"

ProbeAddress::ProbeAddress(const char *foreignHost, const char *foreignService,
                           const char *localHost, int localPort) throw(ProbeException)
{
    struct addrinfo hints, *res, *curr;
    struct sockaddr_in *paddr;
    int n;

    bzero(&hints, sizeof(struct addrinfo));

    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;

    if ((n = getaddrinfo(foreignHost, foreignService, &hints, &res)) != 0)
        throw ProbeException("getaddrinfo error", gai_strerror(n));

    bzero(&localAddr, sizeof(struct sockaddr));

    sockfd = -1;
    for (curr = res; !curr && sockfd < 0; curr = curr->ai_next)
	if ((sockfd = socket(curr->ai_family, SOCK_DGRAM, 0)) >= 0) {
	    if (connect(sockfd, curr->ai_addr, curr->ai_addrlen) < 0) {
		close(sockfd);
		sockfd = -1;
	    }
	}
    
    if (sockfd < 0) {
	freeaddrinfo(res);
	throw ProbeException("Unable to connect by UDP");
    }
	
    localAddrLen = curr->ai_addrlen;
    memcpy(&localAddr, curr->ai_addr, localAddrLen);
    freeaddrinfo(res);

    paddr = (struct sockaddr_in *)&localAddr;

    if (localHost == NULL) {
        if (getsockname(sockfd, &localAddr, &localAddrLen) < 0)
            throw ProbeException("getsockname");
    } else {
        if (inet_pton(AF_INET, localHost, &paddr->sin_addr) != 1)
            throw ProbeException("inet_pton error");
        localAddrLen = sizeof(struct sockaddr_in);
    }

    // anyway, we define the local port ourselves
    paddr->sin_port = htons(localPort);

}

