#include "ProbeRoute.hpp"
#include <assert.h>

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
    assert(res);
    // std::cerr << "out: " 
              // << inet_ntoa(((struct sockaddr_in *)&res->ai_addr)->sin_addr)
              // << std::endl;
    for (curr = res; curr && sockfd < 0; curr = curr->ai_next) {
        // std::cerr << "curr: "
		  // << inet_ntoa(((struct sockaddr_in *)curr->ai_addr)->sin_addr)
                  // << std::endl;
	// if ((sockfd = socket(curr->ai_family, SOCK_DGRAM, 0)) >= 0) {
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
	    // std::printf("sockfd %d opened\n", sockfd);
	    if (connect(sockfd, curr->ai_addr, curr->ai_addrlen) < 0) {
                // std::printf("sockfd %d closed\n", sockfd);
		close(sockfd);
		sockfd = -1;
	    }
	}
    }
    
    if (sockfd < 0) {
	freeaddrinfo(res);
	throw ProbeException("Unable to connect by UDP");
    }

    // std::cerr << "out curr: "
	      // << inet_ntoa(((struct sockaddr_in *)curr->ai_addr)->sin_addr)
	      // << std::endl;

    // std::cerr << "sockfd: " << sockfd << std::endl;
	
    foreignAddrLen = curr->ai_addrlen;
    memcpy(&foreignAddr, curr->ai_addr, foreignAddrLen);
    freeaddrinfo(res);

    paddr = (struct sockaddr_in *)&localAddr;
    localAddrLen = sizeof(struct sockaddr_in);

    if (localHost == NULL) {
        std::cerr << "getsockname" << std::endl;
        if (getsockname(sockfd, &localAddr, &localAddrLen) < 0)
            throw ProbeException("getsockname");

        std::cerr << inet_ntoa(((struct sockaddr_in *)&localAddr)->sin_addr)
		  << " "
		  << ntohs(((struct sockaddr_in *)&localAddr)->sin_port)
                  << std::endl;
    } else {
        if (inet_pton(AF_INET, localHost, &paddr->sin_addr) != 1)
            throw ProbeException("inet_pton error");
    }

    // anyway, we define the local port ourselves
    paddr->sin_port = htons(localPort);

}

