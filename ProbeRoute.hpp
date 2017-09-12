#ifndef _PROBEROUTE_H
#define _PROBEROUTE_H

#include "config.h"

#include <cstdlib>
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
#include <algorithm>
#include <list>

#define CAP_LEN 1514             // Maximum capture length
#define CAP_TIMEOUT 500          // Milliseconds; This timeout is used to arrange
                                 // that the read not necessarily return immediately
                                 // when a packet is seen. In some OS (such as AIX),
                                 // this parameter does not take effect.

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

inline void safeFree(void *point)
{
    if (point) {
        free(point);
        point = NULL;
    }
}

inline const char *nullToEmpty(const char *s)
{
    return (s ? s : "");
}
    
enum ErrType { SYS, MSG };

class ProbeAddressInfo;
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

class ProbeAddressInfo {
    friend class ProbeSock;
    friend std::ostream& operator<<(std::ostream&,
				    const ProbeAddressInfo &);

private:
    // Raw address portion of this object
    sockaddr localAddr, foreignAddr;
    socklen_t localAddrLen, foreignAddrLen;
    std::string device;
    short devMtu;

    // the device information element
    struct deviceInfo {
        std::string name;               // interface name
        short mtu;                      // interface MTU
        short flags;                    // IFF_xxx constants from <net/if.h>
        struct sockaddr *addr;          // primary address
        struct sockaddr *brdaddr;       // broadcast address
        struct sockaddr *netmask;	// netmask address
        deviceInfo(std::string n,
                   short m,
                   short f,
                   struct sockaddr *pa,
                   struct sockaddr *pb,
                   struct sockaddr *pn) :
            name(n), mtu(m), flags(f), addr(pa), brdaddr(pb), netmask(pn) {
        }
        ~deviceInfo() {
            // Nothing to do, we free the resource in clearDeviceInfo().
        }
    };
 
public:
    // Make a socket address for the given host and service or port;
    // Set the local address from given arguments or use connect() to
    // determine outgoing interface.
    
    ProbeAddressInfo(const char *foreignHost, const char *foreignService,
                     const char *localHost = NULL, int localPort = 0,
                     const char *dev = NULL, short mtu = 0) throw(ProbeException);

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

    std::string getDevice() const {
        return device;
    }

    int getDevMtu() const {
        return devMtu;
    }
   

    std::list<deviceInfo> deviceInfoList; // the entry of device linked list

    void getDeviceInfo() throw(ProbeException);
    void clearDeviceInfo();
    void printDeviceInfo();

    // fetch the device information from device list
    deviceInfo& fetchDevice() throw(ProbeException);

};

inline std::ostream& operator<<(std::ostream &output,
				const ProbeAddressInfo &address)
{
 
    struct sockaddr_in *laddr, *faddr;

    laddr = (struct sockaddr_in *)&address.localAddr;
    faddr = (struct sockaddr_in *)&address.foreignAddr;

    output << "local: " << inet_ntoa(laddr->sin_addr) << ":" << ntohs(laddr->sin_port)
           << '\n';
    output << "foreign: " << inet_ntoa(faddr->sin_addr) << ":" << ntohs(faddr->sin_port)
           << '\n';
    output << "device: " << address.device << '\n';
    output << "mtu: " << address.devMtu;

    return output;
}

class ProbePcap {
    friend class ProbeSock;

private:
    pcap_t *handle;
    int linkType;
    int ethLen;
    const std::string DEV;
    const std::string CMD;
    struct bpf_program bpfCode;
public:
    ~ProbePcap();
    ProbePcap(const char *,
	      const char *) throw(ProbeException);
    char *nextPcap(int *len);
};

#if 0
class ProbeSock {
public:
    virtual ~ProbeSock();
    virtual ProbeSock(int protocol);
    // virtual sendPacket();
    // virtual buildHeader();
    // virtual fragPacket();
    // int recvIcmp(char *buf, int len);
    static uint16_t checksum(uint16_t * addr, int len);
    static int do_checksum(u_char *buf, int protocol, int len);

protected:
    int rawfd;
    int pmtu;
    int packLen;
    // ProbeAddress probeAddress;
}
#endif

#endif

