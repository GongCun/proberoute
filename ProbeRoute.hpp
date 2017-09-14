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
#include <assert.h>

#include <iostream>
#include <sstream>
#include <string>
#include <stdexcept>
#include <algorithm>
// #include <list>

#define CAP_LEN 1514             // Maximum capture length
#define CAP_TIMEOUT 500          // Milliseconds; This timeout is used to arrange
                                 // that the read not necessarily return immediately
                                 // when a packet is seen. In some OS (such as AIX),
                                 // this parameter does not take effect.

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define MAXLINE 4096
#define MIN_DF_BUFSIZ 576	 // Minimum reassembly buffer size 
#define MAX_MTU 65535		 // MTU at least 68, max of 64KB 
#define IPPROTO_BAD 143		 // IANA - 143-252 (0x8F-0xFC) UNASSIGNED 
#define TCP_OPT_LEN 40		 // The maximum length of TCP options
#define IP_OPT_LEN 40		 // The maximum length of IP options
#define PROBE_IP_LEN 20		 // IP header length (not include any option)
#define PROBE_TCP_LEN 20	 // TCP header length (not include any option)
#define PROBE_UDP_LEN 8		 // UDP header length 
#define PROBE_ICMP_LEN 8	 // ICMP header length 

inline void safeFree(void *point)
{
    if (point) free(point);
}

inline const char *nullToEmpty(const char *s)
{
    return (s ? s : "");
}
    
// inline uint16_t CKSUM_CARRY(uint32_t x);
// inline uint32_t in_checksum(uint16_t *addr, int len);
// inline uint16_t checksum(uint16_t *addr, int len);

inline uint16_t CKSUM_CARRY(uint32_t x) {
    return (x = (x >> 16) + (x & 0xffff), ~(x + (x >> 16)) & 0xffff);
}

inline uint32_t in_checksum(uint16_t *addr, int len)
{
    uint32_t sum = 0;

    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }

    if (len == 1)
        sum += *(uint16_t *)addr;

    return sum;
}

inline uint16_t checksum(uint16_t *addr, int len)
{
    return CKSUM_CARRY(in_checksum(addr, len));
}


enum ErrType { SYS, MSG };

class ProbeAddressInfo;
class ProbeSock;
class ProbePcap;
class TcpProbeSock;
class UdpProbeSock;
class IcmpProbeSock;
class ProbeException;


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
    friend std::ostream& operator<<(std::ostream&,
				    const ProbeAddressInfo &);

private:
    // Raw address portion of this object
    sockaddr localAddr, foreignAddr;
    socklen_t localAddrLen, foreignAddrLen;
    std::string device;
    u_short devMtu;

    // the device information element
    struct deviceInfo {
        std::string name;               // interface name
        u_short mtu;			// interface MTU
        short flags;                    // IFF_xxx constants from <net/if.h>
        struct sockaddr *addr;          // primary address
        struct sockaddr *brdaddr;       // broadcast address
        struct sockaddr *netmask;	// netmask address
        struct deviceInfo *next;        // next of these structures
        deviceInfo(): name(""), mtu(0), flags(0),
                      addr(NULL), brdaddr(NULL), netmask(NULL),
                      next(NULL) {}
	~deviceInfo() {
	    safeFree(addr); safeFree(brdaddr); safeFree(netmask);
	}
    };
 
public:
    // Make a socket address for the given host and service or port;
    // Set the local address from given arguments or use connect() to
    // determine outgoing interface.
    
    ProbeAddressInfo(const char *foreignHost, const char *foreignService,
                     const char *localHost = NULL, int localPort = 0,
                     const char *dev = NULL, u_short mtu = 0) throw(ProbeException);

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
   

    struct deviceInfo *deviceInfoList; // the entry of device linked list
    void getDeviceInfo() throw(ProbeException);
    void freeDeviceInfo();
    void printDeviceInfo();

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

class ProbeSock {
    // friend std::ostream& operator<<(std::ostream&,
				    // const ProbeSock&);
public:
    static int openSock(const int protocol) throw(ProbeException);
    // virtual std::ostream& print(std::ostream &output);
    virtual ~ProbeSock() { close(rawfd); }
    ProbeSock(const int proto, u_short mtu,
              uint16_t id = (u_short)time(0) & 0xffff,
              int len = 0, u_char *buf = NULL):
	protocol(proto), rawfd(openSock(proto)), pmtu(mtu), ipid(id),
        ipoptLen(len), iphdrLen(PROBE_IP_LEN) {
        assert(len >= 0);
        if (len) {
            if (!buf) {
                //  Default IP timestamp option, only used to implement *BAD* IP length
                u_char *p = ipopt;
                *p++ = 0x44;             // IP timestamp option
                *p++ = 40;		 // *BAD* length of option
                *p++ = 5;		 // the pointer to the entry
                *p++ = 0;		 // record only timestamps
                ipoptLen = 4;
            } else {
                memcpy(ipopt, buf, len);
            }
            iphdrLen += ipoptLen;
        }
    }

    // virtual int sendPacket() throw(ProbeException);
    // virtual sendFragPacket();
    int buildIpHeader(u_char *buf, int protoLen, struct in_addr src, struct in_addr dst,
                      u_char ttl, u_short flagFrag);

    virtual void buildProtocolHeader() {}
    virtual void buildProtocolPacket() {}

    int getIphdrLen() {
	return iphdrLen;
    }
    // virtual recvProtocolPacket() = 0;
    // int recvIcmp(char *buf, int len);

protected:
    const int protocol;
    int rawfd;
    u_short pmtu;
    uint16_t ipid;
    u_char ipopt[IP_OPT_LEN];
    int ipoptLen;
    int iphdrLen;
    // struct sockaddr saDest;
    // int packLen;
    // ProbeAddress probeAddress;
};

class TcpProbeSock: public ProbeSock {
public:
    TcpProbeSock(u_short mtu, uint16_t id, struct in_addr src, struct in_addr dst,
		 int iplen = 0, u_char *ipbuf = NULL, int len = 0, u_char *buf = NULL):
	ProbeSock(IPPROTO_TCP, mtu, id, iplen, ipbuf), srcAddr(src), dstAddr(dst),
	tcpoptLen(len), tcphdrLen(PROBE_TCP_LEN) {
        assert(len >= 0);
        if (len) {
            if (!buf) {
                u_char *p = tcpopt;
                *p++ = 2;		 // TCP mss option
                *p++ = 4;		 // option len

                // MSS don't need to subtract the length of MSS option itself, but should
                // subtract the IP options and other length of TCP options (e.g. TCP
                // timestamps options)
                u_short mss = pmtu - iphdrLen - PROBE_TCP_LEN; 
                assert(mss > 0);
                *(u_short *)p= htons(mss);
                tcpoptLen = 4;
            } else {
                memcpy(tcpopt, buf, len);
            }
            tcphdrLen += tcpoptLen;
        }
    }
	
    // using ProbeSock::buildProtocolHeader;
    int buildProtocolHeader(u_char *buf, int protoLen, u_short sport, u_short dport,
                            uint32_t seq, uint32_t ack, u_char flags = TH_SYN, bool badsum = false);

    // using ProbeSock::buildProtocolPacket;
    int buildProtocolPacket(u_char *buf, int protoLen, struct in_addr src, struct in_addr dst,
			    u_char ttl, u_short flagFrag, u_short sport, u_short dport,
			    uint32_t seq, uint32_t ack);

    int getTcphdrLen() {
	return tcphdrLen;
    }
private:
    struct in_addr srcAddr, dstAddr;
    u_char tcpopt[TCP_OPT_LEN];
    int tcpoptLen;
    int tcphdrLen;
};


#endif

