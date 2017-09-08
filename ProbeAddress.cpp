#include "ProbeRoute.hpp"
// using namespace std;

ProbeAddress::ProbeAddress(const char *host, const char *service) throw(ProbeException)
{
    struct addrinfo hints, *res;
    int n;

    bzero(&hints, sizeof(struct addrinfo));

    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;

    if ((n = getaddrinfo(host, service, &hints, &res)) != 0)
        throw ProbeException("getaddrinfo error", gai_strerror(n));

    bzero(&addr, sizeof(struct sockaddr));
    memcpy(&addr, res->ai_addr, sizeof(struct sockaddr));
    addrlen = res->ai_addrlen;

    freeaddrinfo(res);
}

ProbeAddress::ProbeAddress(const char *host, int port) throw(ProbeException)
{
    char service[6];
    struct addrinfo hints, *res;
    int n;

    snprintf(service, sizeof(service), "%d", port);
    bzero(&hints, sizeof(struct addrinfo));

    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;

    if ((n = getaddrinfo(host, service, &hints, &res)) != 0)
        throw ProbeException("getaddrinfo error", gai_strerror(n));

    bzero(&addr, sizeof(struct sockaddr));
    memcpy(&addr, res->ai_addr, sizeof(struct sockaddr));
    addrlen = res->ai_addrlen;

    freeaddrinfo(res);
}

