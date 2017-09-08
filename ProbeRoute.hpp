#ifndef _PROBEROUTE_H
#define _PROBEROUTE_H

#include <cstdlib>
// #include <errno.h>
// #include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>              // getaddrinfo, freeaddrinfo
#include <sys/time.h>
#include <time.h>
#include <sys/select.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#ifdef _LINUX
# ifndef __USE_BSD
#  define __USE_BSD 1           /* Use BSD format of ip header */
# endif
# ifndef __FAVOR_BSD
#  define __FAVOR_BSD 1         /* Use BSD format of tcp header */
# endif
#endif

/* Get interface MTU */
#include <sys/ioctl.h>
#include <net/if.h>		/* struct ifreq */

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <pcap.h>
#ifdef _AIX
# include <net/bpf.h>
# include <netinet/if_ether.h>
#else
# include <net/ethernet.h>
#endif

#include <setjmp.h>
#include <signal.h>
#include <strings.h>		// bzero()

#include <iostream>
#include <string>
#include <stdexcept>
#include <vector>

#define CAP_LEN 1514             // Maximum capture length
#define CAP_TIMEOUT 500          // Milliseconds; This timeout is used to arrange
                                 // that the read not necessarily return immediately
                                 // when a packet is seen. In some OS (such as AIX),
                                 // this parameter does not take effect.

class ProbeAddress;
class ProbeSock;
class ProbePcap;

class ProbeException : public std::runtime_error {
public:
    ProbeException(const std::string &message) throw();
    ProbeException(const std::string &message,
                   const std::string &detail) throw();
};

class ProbeAddress {
    friend class ProbeSock;
    friend std::ostream& operator<<(std::ostream&, const ProbeAddress &);

public:
    // Make a socket address for the given host and service or port
    ProbeAddress(const char *host, const char *service) throw(ProbeException);

    // Return a string representation of the address
    std::string getAddress() const throw(ProbeException);

    // Return a numeric value of the port
    int getPort() const throw(ProbeException);

    // Return a pointer to the sockaddr
    sockaddr *getSockaddr() {
        return &addr;
    }

    // Return the length of the sockaddr structure
    socklen_t getSockaddrLen() {
        return addrlen;
    }
    
private:
    // Raw address portion of this object
    sockaddr addr;
    socklen_t addrlen;
};

inline std::ostream& operator<<(std::ostream &output,
				const ProbeAddress &address)
{
    struct sockaddr_in *paddr;

    paddr = (struct sockaddr_in *)&address.addr;

    output << inet_ntoa(paddr->sin_addr) << ":" << ntohs(paddr->sin_port);

    return output;
}


#if 0
class ProbePcap {
    friend class ProbeSock;
private:
    std::string CMD;
    pcap_t handle;
    int linkType;
    int ethLen;
public:
    ~ProbePcap();
    ProbePcap(const std::string CMD =
              "icmp[0:1] == 3 or icmp[0:1] == 11 or icmp[0:1] == 12",
              const char *device);
    char *nextPcap(int *len);
};

class ProbeSock {
public:
    virtual ~ProbeSock();
    ProbeAddress getLocalAddress() throw(ProbeException);
    int recvIcmp(char *buf, int len);
    virtual sendPacket();
    virtual buildHeader();
    virtual fragPacket();

protected:
    ProbeSock();
    int sockfd;
    void createSock(int protocol);
}

#endif

#endif
