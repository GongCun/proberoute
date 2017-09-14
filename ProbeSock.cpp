#include "ProbeRoute.hpp"
#include <assert.h>


int ProbeSock::openSock(const int protocol) throw(ProbeException)
{
    int rawfd;
    std::stringstream msg;
    const int on = 1;
    const int size = MAX_MTU;

#ifdef _LINUX
    if ((rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	throw ProbeException("socket IPPROTO_RAW");
#else
    if ((rawfd = socket(AF_INET, SOCK_RAW, protocol)) < 0) {
	msg << "socket protocol " << protocol;
	throw ProbeException(msg.str());
    }
#endif

    if (setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	throw ProbeException("setsockopt IP_HDRINCL");

    // OK if setsockopt fails 
    setsockopt(rawfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    setsockopt(rawfd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    
    if (setsockopt(rawfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0)
	throw ProbeException("setsockopt SO_BROADCAST");

    return rawfd;
}



// ProbeSock::ProbeSock(const int protocol, ProbeAddressInfo &addrInfo):
//     rawfd(openSock(protocol)), pmtu(addrInfo.getDevMtu()) {
// }


int ProbeSock::buildIpHeader(u_char *buf, int protoLen, struct in_addr src, struct in_addr dst,
                             u_char ttl, u_short flagFrag) throw(ProbeException)
// protoLen = protocol header length + payload length
{
    struct ip *ip;

    bzero(buf, iphdrLen);

    ip = (struct ip *)buf;
    ip->ip_hl = iphdrLen >> 2;
    ip->ip_v = 4;
    ip->ip_tos = 0;


#ifdef _LINUX
    ip->ip_len = htons(iphdrLen + protoLen);
#else
    ip->ip_len = iphdrLen + protoLen;
#endif

    // Don't change the value of ip_id
    ip->ip_id = htons(ipid);

#ifdef _LINUX
    ip->ip_off = htons(flagFrag);
#else
    ip->ip_off = flagFrag;
#endif

    ip->ip_ttl = ttl;
    ip->ip_p = protocol;
    ip->ip_src.s_addr = src.s_addr;
    ip->ip_dst.s_addr = dst.s_addr;

    if (iphdrLen > PROBE_IP_LEN) {
        assert(iphdrLen - PROBE_IP_LEN == ipoptLen);
        u_char *p = buf + PROBE_IP_LEN;
        memcpy(p, ipopt, ipoptLen);
    }

    ip->ip_sum = 0;
    if (do_checksum(buf, IPPROTO_IP, 0) < 0)
        throw ProbeException("do_checksum IPPROTO_IP");

    return iphdrLen;

}

	