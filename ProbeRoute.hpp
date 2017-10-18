#ifndef _PROBEROUTE_H
#define _PROBEROUTE_H

#include "config.h"

#include <cstdlib>
#include <cstdio>
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

/* Get interface MTU and routing information */
#include <sys/ioctl.h>
#include <net/if.h>		/* struct ifreq */
#ifdef HAVE_SOCKADDR_DL_STRUCT
#include <net/if_dl.h>		/* struct sockaddr_dl */
#endif

#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>		/* struct rt_msghdr */
#endif

#ifdef _LINUX
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <pcap.h>
#ifdef _AIX
# include <net/bpf.h>
# include <netinet/if_ether.h>
#elif defined HAVE_NET_ETHERNET_H
# include <net/ethernet.h>
#endif

#include <setjmp.h>
#include <signal.h>
#include <strings.h>		 // bzero()
#include <assert.h>

#if defined _LINUX || defined _CYGWIN
#include <typeinfo>
#endif
#include <iostream>
#include <sstream>
#include <string>
#include <cstring>		 // memset(), strcmp(), ...
#include <stdexcept>
#include <algorithm>
#include <vector>

#ifdef _CYGWIN
extern "C" {
#include "getmac.h"
}
#endif

#ifdef _CYGWIN
#define CAP_LEN 65536            // from WinPcap example (Interpreting the packets)
#else
#define CAP_LEN 1514             // Maximum capture length
#endif
#ifdef _CYGWIN
#define CAP_TIMEOUT 500
#else
#define CAP_TIMEOUT 1            // Milliseconds; This timeout is used to arrange
                                 // that the read not necessarily return immediately
                                 // when a packet is seen. In some OS (such as AIX),
                                 // this parameter does not take effect.
#endif
#define GUESS_CAP_LEN 1514

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define MAXLINE 4096
#define MIN_DF_BUFSIZ 576	 // Minimum reassembly buffer size 
#define MAX_MTU 65535		 // MTU at least 68, max of 64KB 
#define IPPROTO_BAD 143		 // IANA - 143-252 (0x8F-0xFC) UNASSIGNED 
#define TCP_OPT_LEN 40		 // The maximum length of TCP options
#define IP_OPT_LEN 44		 // The maximum length of IP options
#define PROBE_IP_LEN 20		 // IP header length (not include any option)
#define PROBE_TCP_LEN 20	 // TCP header length (not include any option)
#define PROBE_UDP_LEN 8		 // UDP header length 
#define PROBE_ICMP_LEN 8	 // ICMP header length 
#define MAX_GATEWAY 9		 // Maximum source route records

#ifndef HAVE_ICMP_STRUCT        // cygwin on Windows don't define ICMP header
struct icmp 
{
    uint8_t icmp_type;      // type of message
    uint8_t icmp_code;      // type sub code
    uint16_t icmp_cksum;    // ones complement checksum of struct
    union 
    {
        struct ih_idseq 
        {
            uint16_t icd_id;
            uint16_t icd_seq;
        } ih_idseq;         // for ICMP_ECHO, ICMP_TSTAMP
        uint32_t ih_void;   // for ICMP_UNREACH
    } icmp_hun;

#define icmp_id   icmp_hun.ih_idseq.icd_id
#define icmp_seq  icmp_hun.ih_idseq.icd_seq
#define icmp_void icmp_hun.ih_void

    union 
    {
        struct 
        {
            uint32_t its_otime;
            uint32_t its_rtime;
            uint32_t its_ttime;
        } id_ts;            // for ICMP_TSTAMP
        struct 
        {
            struct ip idi_ip;
        } id_ip;
    } icmp_dun;
#define icmp_otime icmp_dun.id_ts.its_otime
#define icmp_rtime icmp_dun.id_ts.its_rtime
#define icmp_ttime icmp_dun.id_ts.its_ttime
};

#define ICMP_ECHOREPLY          0               /* Echo Reply */
#define ICMP_UNREACH            3               /* dest unreachable, codes: */
#define ICMP_REDIRECT           5               /* Redirect (change route) */
#define ICMP_ECHO               8               /* Echo Request */
#define ICMP_ROUTERADVERT       9               /* router advertisement */
#define ICMP_ROUTERSOLICIT      10              /* router solicitation */
#define ICMP_TIMXCEED           11              /* time exceeded, code: */
#define ICMP_PARAMPROB          12              /* ip header bad */
#define ICMP_TSTAMP             13              /* timestamp request */
#define ICMP_TSTAMPREPLY        14              /* timestamp reply */
#define ICMP_IREQ               15              /* information request */
#define ICMP_IREQREPLY          16              /* information reply */
#define ICMP_MASKREQ            17              /* address mask request */
#define ICMP_MASKREPLY          18              /* address mask reply */

/* UNREACH codes */
#define ICMP_UNREACH_NEEDFRAG   4               /* IP_DF caused drop */

/* TIMEXCEED codes */
#define ICMP_TIMXCEED_INTRANS   0               /* ttl==0 in transit */
#define ICMP_TIMXCEED_REASS     1               /* ttl==0 in reass */


#endif

#ifndef HAVE_ICMP_NEXTMTU
// Path MTU Discovery (RFC1191)
struct my_pmtu {
    u_short ipm_void;
    u_short ipm_nextmtu;
};
#endif


extern sigjmp_buf jumpbuf;
extern int verbose;
// extern int protocol;
extern int srcport;
extern const char *device;
extern int nquery;
extern int waittime;
extern int firstttl, maxttl;
extern int fragsize;
extern int mtu;
extern int conn;
extern int badsum, badlen;
extern const char *host, *service, *srcip;
extern u_char tcpFlags;
extern u_char icmpFlags;
extern u_char tcpopt[TCP_OPT_LEN], ipopt[IP_OPT_LEN];
extern u_char *optptr;
extern std::vector<int> protoVec;
extern std::string captureFunc;
extern struct sockaddr *Netmask;  // for CYGWIN capture filter in case
#ifdef _CYGWIN
extern const u_char EtherLen;
extern u_char EtherHdr[];	  // for keep the MAC address and type
extern pcap_t *Sendfp;
#endif

inline int Rand()
{
    // only need call srand() once
    static bool init = false;
    
    if (!init) {
        srand(time(0));
        init = true;
    }
    return rand();
}
 
inline void safeFree(void *point)
{
    if (point) free(point);
}

inline const char *nullToEmpty(const char *s)
{
    return (s ? s : "");
}
    
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

inline double delta(struct timeval *last)
{
    struct timeval now;
    
    if (gettimeofday((&now), NULL) == -1)
        return -1;

    if ((now.tv_usec -= last->tv_usec) < 0) {
        --now.tv_sec;
        now.tv_usec += 1000000;
    }
    now.tv_sec -= last->tv_sec;
    return now.tv_sec * 1000.0 + now.tv_usec / 1000.0;
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
    struct sockaddr localAddr, foreignAddr;
    socklen_t localAddrLen, foreignAddrLen;
    std::string device;
    u_short devMtu;
    bool sameLan;
    char strDestination[INET_ADDRSTRLEN];
    char strGateway[INET_ADDRSTRLEN];
    char strDestinationMask[INET_ADDRSTRLEN];

    // the device information element
    struct deviceInfo {
        std::string name;               // interface name
        u_short mtu;			// interface MTU
        short flags;                    // IFF_xxx constants from <net/if.h>
        struct sockaddr *addr;          // primary address
        struct sockaddr *brdaddr;       // broadcast address
        struct sockaddr *netmask;	// netmask address
        struct sockaddr *dstaddr;	// point-to-point destination address
        struct deviceInfo *next;        // next of these structures
        deviceInfo(): name(""), mtu(0), flags(0),
                      addr(NULL), brdaddr(NULL), netmask(NULL),
		      dstaddr(NULL),
                      next(NULL) {}
	~deviceInfo() {
	    safeFree(addr); safeFree(brdaddr); safeFree(netmask);
	}

        void print();
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

    bool isSameLan() const {
        return sameLan;
    }

    const char *getGateway() const {
        return strGateway;
    }
            
    const char *getDestination() const {
        return strDestination;
    }

    const char *getDestinationMask() const {
        return strDestinationMask;
    }
            
            
    struct deviceInfo *deviceInfoList; // the entry of device linked list
    void getDeviceInfo() throw(ProbeException);
    void freeDeviceInfo();
    void printDeviceInfo();
    void getRouteInfo(const struct in_addr *) throw(ProbeException);
 
};

inline std::ostream& operator<<(std::ostream &output,
				const ProbeAddressInfo &address)
{
 
    struct sockaddr_in *laddr, *faddr;

    laddr = (struct sockaddr_in *)&address.localAddr;
    faddr = (struct sockaddr_in *)&address.foreignAddr;

    output << "local: " << inet_ntoa(laddr->sin_addr) << ":" << ntohs(laddr->sin_port)
           << std::endl;
    output << "foreign: " << inet_ntoa(faddr->sin_addr) << ":" << ntohs(faddr->sin_port)
           << std::endl;
    output << "device: " << address.device << std::endl;
    output << "mtu: " << address.devMtu << std::endl;

    if (address.strDestination[0] != 0)
        output << "destination: " << address.strDestination << std::endl;

    if (address.strGateway[0] != 0)
        output << "gateway: " << address.strGateway << std::endl;

    if (address.strDestinationMask[0] != 0)
        output << "netmask: " << address.strDestinationMask << std::endl;

    output << (address.sameLan ? "in the same lan" : "not in the same lan");

    return output;
}

extern "C" {
    // thread functions for capture the packets
    void *recvPkt(void *);
    void *captPkt(void *);
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
    ProbePcap(const char *,
			       const char *) throw(ProbeException);

    ~ProbePcap() {
#ifndef _CYGWIN 		  // pcap_close will trigger pcap_next error on Windows
#ifdef HAVE_PCAP_CLOSE
        pcap_close(handle);
#elif defined HAVE_PCAP_FREECODE
        pcap_freecode(&bpfCode);
#endif
#endif
	// std::cerr << "EXIT PCAP" << std::endl;
    }

    inline const int getEthLen() const {
        return ethLen;
    }

    const u_char *nextPcap(int *len);
}; // class ProbePcap

////////////////////////////////////////
class ProbeSock {
    friend std::ostream& operator<<(std::ostream&,
				    const ProbeSock&);
public:
    virtual ProbeSock& operator++() {
        ++ipid;
        return *this;
    }

    static int openSock(const int protocol) throw(ProbeException);
    // If we copy anonymous class to vector, we can't close the FD
    virtual ~ProbeSock() {
        close(rawfd);
        // std::cerr << "I'm freed" << std::endl;
    }
    ProbeSock(
	const int proto,
	u_short mtu,
	struct in_addr src,
	struct in_addr dst,
	int len = 0,
	u_char *buf = NULL,
	uint16_t id = (u_short)Rand() & 0xffff
    ):
	protocol(proto),
	rawfd(openSock(proto)),
	pmtu(mtu),
	srcAddr(src),
	dstAddr(dst),
	ipoptLen(len),
        iphdrLen(PROBE_IP_LEN),
	ipid(id)
	{
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

    ssize_t sendPacket(const void *,
			       size_t, int,
			       const struct sockaddr *,
			       socklen_t) throw(ProbeException);

    int sendFragPacket(const u_char *tcpbuf, const int packlen,
		       const u_char ttl, const int fragsize,
		       const struct sockaddr *to, socklen_t tolen) throw(ProbeException);
	
    int buildIpHeader(u_char *buf, int protoLen, u_char ttl, u_short flagFrag);

    virtual int buildProtocolHeader(
	u_char *buf,
	int protoLen,
	bool badsum = false
    ) = 0;

    virtual int buildProtocolPacket(
	u_char *buf,
	int protoLen,
	u_char ttl,
	u_short flagFrag = IP_DF,
	bool badsum = false
    );

    virtual int recvIcmp(const u_char *buf, const int len);

    int getIphdrLen() const {
	return iphdrLen;
    }

    virtual int getProtocolHdrLen() const = 0;

    int getPmtu() const {
        return pmtu;
    }

    void setPmtu(u_short mtu) {
        pmtu = mtu;
    }
    void setPmtu(int mtu) {
        pmtu = (u_short)mtu;
    }
                

    in_addr getSrcAddr() const {
	return srcAddr;
    }

    in_addr getDstAddr() const {
	return dstAddr;
    }

    int getProtocol() const {
	return protocol;
    }

    int getRawfd() const {
        return rawfd;
    }
            
protected:
    const int protocol;
    int rawfd;
    u_short pmtu;
    struct in_addr srcAddr, dstAddr;
    u_char ipopt[IP_OPT_LEN];
    int ipoptLen;
    int iphdrLen;
    uint16_t ipid;

}; // class ProbeSock

class IcmpProbeSock: public ProbeSock {

    friend std::ostream& operator<<(std::ostream& output,
                                    const IcmpProbeSock& probe);

private:
    u_char icmpType;		  // ICMP_ECHO, ICMP_TSTAMP, ...
    int icmphdrLen;
    u_short icmpId;
    u_short icmpSeq;

public:
    IcmpProbeSock(
	u_short mtu,
	struct in_addr src,
	struct in_addr dst,
	u_char flags = ICMP_ECHO, // ICMP_ECHO or ICMP_TSTAMP
	int iplen = 0,
	u_char *ipbuf = NULL
    ):
	ProbeSock(IPPROTO_ICMP, mtu, src, dst, iplen, ipbuf),
	icmpType(flags),
	icmphdrLen(flags == ICMP_TSTAMP ? 20 : 8),
	icmpId(getpid() & 0xffff),
	icmpSeq(0)
	{
    }
    
    // use the base class destructor
    
    int buildProtocolHeader(
	u_char *buf,
	int protoLen,
	bool badsum
    );

    int getProtocolHdrLen() const {
	return icmphdrLen;
    }

    int getIcmpSeq() const {
	return icmpSeq;
    }

    virtual IcmpProbeSock& operator++() {
        ++ipid;
        ++icmpSeq;
        return *this;
    }

    virtual int recvIcmp(const u_char *buf, const int len);
}; // class IcmpProbeSock

class UdpProbeSock: public ProbeSock {

    friend std::ostream& operator<<(std::ostream& output,
                                    const UdpProbeSock& probe);

private:
    u_short sport, dport;
    
public:
    UdpProbeSock(
	u_short mtu,
	struct in_addr src,
	struct in_addr dst,
	u_short _sport,
	u_short _dport,
	int iplen = 0,
	u_char *ipbuf = NULL
    ):
	ProbeSock(IPPROTO_UDP, mtu, src, dst, iplen, ipbuf),
	sport(_sport),
	dport(_dport)
	{
    }
    
    // use the base class destructor
    
    int getProtocolHdrLen() const { // UDP header length is fixed
	return PROBE_UDP_LEN;
    }

    int buildProtocolHeader(
	u_char *buf,
	int protoLen,
	bool badsum
    );

    virtual UdpProbeSock& operator++() {
        // classic traceroute only increment the destination port
        // ++ipid;
        ++dport;
        return *this;
    }

    virtual int recvIcmp(const u_char *buf, const int len);
}; // class UdpProbeSock

class TcpProbeSock: public ProbeSock {
    friend std::ostream& operator<<(std::ostream& output,
                                    const TcpProbeSock& probe);
public:
    TcpProbeSock(
	u_short mtu,
	struct in_addr src,
	struct in_addr dst,
	u_short _sport,
	u_short _dport,
	int iplen = 0,
	u_char *ipbuf = NULL,
	int len = 0,
	u_char *buf = NULL,
	uint16_t id = (u_short)time(0) & 0xffff,
	uint32_t seq = 0,
	uint32_t ack = 0,
	u_char flags = TH_SYN
    ):
	ProbeSock(IPPROTO_TCP, mtu, src, dst, iplen, ipbuf, id),
	tcpoptLen(len),
	tcphdrLen(PROBE_TCP_LEN),
	sport(_sport),
	dport(_dport),
	tcpseq(seq),
	tcpack(ack),
	tcpflags(flags)
	{
        assert(len >= 0);
        if (len) {
            if (!buf) {
                // *NOTE* - The MSS option applies only to SYN packet, and the SYN packet
                // has no payload (just TCP header).
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
	
    int buildProtocolHeader(
	u_char *buf,
	int protoLen,
	bool badsum
    );

    int recvTcp(const u_char *buf, int len);

    static bool capWrite(
        const u_char *buf,
        int len,
        u_short sport,
        u_short dport,
        uint16_t& ipid,
        uint32_t& seq,
        uint32_t& ack,
	u_char *ipopt,
	int &ipoptlen,
	u_char *tcpopt,
	int& tcpoptlen
    );

    static int nonbConn(int fd, const struct sockaddr *addr, socklen_t addrlen,
			int nsec, unsigned long msec);
    
    int getProtocolHdrLen() const {
	return tcphdrLen;
    }

    int getTcpDstPort() const {
	return dport;
    }

private:
    u_char tcpopt[TCP_OPT_LEN];
    int tcpoptLen;
    int tcphdrLen;
    u_short sport, dport;
    uint32_t tcpseq, tcpack;
    u_char tcpflags;
}; // class TcpProbeSock

inline std::ostream& operator<<(std::ostream& output,
				const ProbeSock& probe)
{
    output << "srcAddr: " << inet_ntoa(probe.srcAddr) << std::endl;
    output << "dstAddr: " << inet_ntoa(probe.dstAddr) << std::endl;
    output << "protocol: " << probe.protocol << std::endl;
    output << "rawfd: " << probe.rawfd << std::endl;
    output << "pmtu: " << probe.pmtu << std::endl;
    output << "iphdrLen: " << probe.iphdrLen << std::endl;
    std::printf("ipid: 0x%04x\n", htons(probe.ipid));

    output << "ipopt: ";
    // Should use boost::format or std::putf
    for (int i = 0; i < probe.ipoptLen; i++)
        std::printf("%02x ", probe.ipopt[i]);
    if (!probe.ipoptLen) output << "null"; 

    return output;
}

inline std::ostream& operator<<(std::ostream& output,
				const TcpProbeSock& probe)
{
    output << (const ProbeSock &)probe << std::endl;
    
    output << "tcphdrLen: " << probe.tcphdrLen << std::endl;
    output << "tcpopt: ";
    // Should use boost::format or std::putf
    for (int i = 0; i < probe.tcpoptLen; i++)
        std::printf("%02x%s", probe.tcpopt[i], i == probe.tcpoptLen - 1  ? "\n" : " ");
    if (!probe.tcpoptLen) output << "null" << std::endl;

    output << "sport: " << probe.sport << std::endl;
    output << "dport: " << probe.dport << std::endl;
    output << "tcpseq: " << probe.tcpseq << std::endl;
    output << "tcpack: " << probe.tcpack;

    return output;
}

inline std::ostream& operator<<(std::ostream& output,
				const IcmpProbeSock& probe)
{
    output << (const ProbeSock &)probe << std::endl;
    
    output << "icmpType: " << probe.icmpType << std::endl;
    output << "icmphdrLen: " << probe.icmphdrLen << std::endl;
    output << "icmpId: " << probe.icmpId << std::endl;
    output << "icmpSeq: " << probe.icmpSeq;

    return output;
}

inline std::ostream& operator<<(std::ostream& output,
				const UdpProbeSock& probe)
{
    output << (const ProbeSock &)probe << std::endl;
    output << "sport: " << probe.sport << std::endl;
    output << "dport: " << probe.dport;

    return output;
}

int parseOpt(int argc, char **argv, std::string&);

int setAddrByName(const char *host, struct in_addr *addr);

#endif
