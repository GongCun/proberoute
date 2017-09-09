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

enum ErrType { SYS, MSG };

class ProbeAddress;
class ProbeSock;
class ProbePcap;

class ProbeException : public std::exception {
private:
    std::string msg;
public:
    ~ProbeException() throw() {};
    ProbeException(const std::string &, ErrType type = SYS) throw();
    ProbeException(const std::string &,
                   const std::string &) throw();
    const char *what() const throw();
};

class ProbeAddress {
    friend class ProbeSock;
    friend std::ostream& operator<<(std::ostream&, const ProbeAddress &);

public:
    // Make a socket address for the given host and service or port;
    // Set the local address from given arguments or use connect() to
    // determine outgoing interface.
    
    ProbeAddress(const char *foreignHost, const char *foreignService,
		 const char *localHost = NULL, int localPort = 0) throw(ProbeException);

    // Make a socket address for the given host and service or port
    // ProbeAddress(const char *host, int port) throw(ProbeException);

    sockaddr *getLocalSockaddr() {
        return &localAddr;
    }

    socklen_t getLocalSockaddrLen() const {
        return localAddrLen;
    }

    sockaddr *getForeignSockaddr() {
        return &foreignAddr;
    }

    socklen_t getForeignSockaddrLen() const {
        return foreignAddrLen;
    }
    
private:
    // Raw address portion of this object
    int sockfd;			// only for fetching interface
				// information, not to transfer data.
    sockaddr localAddr, foreignAddr;
    socklen_t localAddrLen, foreignAddrLen;
};

inline std::ostream& operator<<(std::ostream &output,
				const ProbeAddress &address)
{
 
    struct sockaddr_in *laddr, *faddr;

    laddr = (struct sockaddr_in *)&address.localAddr;
    faddr = (struct sockaddr_in *)&address.foreignAddr;

    output << "local: " << inet_ntoa(laddr->sin_addr) << ":" << ntohs(laddr->sin_port);
    output << '\n';
    output << "foreign: " << inet_ntoa(faddr->sin_addr) << ":" << ntohs(faddr->sin_port);

    return output;
}

class ProbePcap {
    friend class ProbeSock;

private:
    std::string CMD;
    pcap_t *handle;
    int linkType;
    int ethLen;
    char *device;
public:
    ~ProbePcap();
    ProbePcap(char *device,
	      const std::string CMD) throw(ProbeException);
    char *nextPcap(int *len);
};

#if 0
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
    int rawfd;
    void createSock(int protocol);
}

#endif

#endif
