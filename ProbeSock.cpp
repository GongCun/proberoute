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


int ProbeSock::buildIpHeader(u_char *buf, int protoLen, u_char ttl, u_short flagFrag)
// protoLen = protocol header length + payload length
{
    struct ip *ip;

    assert(protoLen >= 0);

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

    // Don't change the value of ip_id. If the ip_id is 0, system will arrange a
    // random ID, so the fragment packet can't be reassembled.
    ip->ip_id = htons(ipid);
    // std::cerr << "ip_id = " << ipid << std::endl;

#ifdef _LINUX
    ip->ip_off = htons(flagFrag);
#else
    ip->ip_off = flagFrag;
#endif

    ip->ip_ttl = ttl;
    ip->ip_p = protocol;
    ip->ip_src.s_addr = srcAddr.s_addr;
    ip->ip_dst.s_addr = dstAddr.s_addr;

    if (iphdrLen > PROBE_IP_LEN) {
        assert(iphdrLen - PROBE_IP_LEN == ipoptLen);
        u_char *p = buf + PROBE_IP_LEN;
        memcpy(p, ipopt, ipoptLen);
    }

    ip->ip_sum = 0;
    ip->ip_sum = checksum((uint16_t *)buf, iphdrLen);

    return iphdrLen;

}



int ProbeSock::sendPacket(const void *buf, size_t buflen, int flags, const struct sockaddr *to, socklen_t tolen)
    throw(ProbeException)
{
    int len;
    if ((len = sendto(rawfd, buf, buflen, flags, to, tolen)) != buflen)
	throw ProbeException("sendto error");

    return len;
}

int ProbeSock::sendFragPacket(const u_char *tcpbuf, const int packlen,
			      const u_char ttl, const int fragsize,
			      const struct sockaddr *to, socklen_t tolen) throw(ProbeException)
{
    u_char buf[MAX_MTU];
    const u_char *ptr = tcpbuf;
    int remlen = packlen, offset = 0, sendlen;
    int iplen;
    u_short flags;

    if (fragsize % 8)
        throw ProbeException("fragment size must be a multiple of 8");

    while (remlen) {
	sendlen = std::min(remlen, fragsize);
        if (remlen <= fragsize) {
            if (remlen == packlen) // if packlen <= fragment size, can't be split
                flags = IP_DF;
            else		   // exactly the last packet
                flags = offset >> 3;
        } else {
            // if (remlen == packlen) // the first packet, no offset
                // flags = IP_MF;
            // else                   // neither the first nor the last packet
                flags = (offset >> 3) | IP_MF;
        }

        iplen = buildIpHeader(buf, sendlen, ttl, flags);
	memcpy(buf + iplen, ptr, sendlen);
	sendPacket(buf, iplen + sendlen, 0, to, tolen);
	offset += sendlen;
	remlen -= sendlen;
	ptr += sendlen;
    }

    return packlen;
}

	
int TcpProbeSock::buildProtocolHeader(u_char *buf, int protoLen, u_short sport, u_short dport,
				      uint32_t seq, uint32_t ack, u_char flags, bool badsum)
{
    struct tcphdr *tcp;
    u_char *p;
    uint32_t sum = 0;

    assert(protoLen >= tcphdrLen);
    bzero(buf, tcphdrLen);
    tcp = (struct tcphdr *)buf;

    tcp->th_sport = htons(sport);
    tcp->th_dport = htons(dport);
    tcp->th_seq = htonl(seq);
    tcp->th_ack = htonl(ack);
    tcp->th_x2 = 0;
    tcp->th_off = tcphdrLen >> 2;
    tcp->th_flags = flags;
    tcp->th_urp = 0;              // urgent pointer
    tcp->th_win = htons(MAX_MTU); // default 65535
    tcp->th_sum = 0;              // calculate later

    if (tcphdrLen > PROBE_TCP_LEN) {
        assert(tcphdrLen - PROBE_TCP_LEN == tcpoptLen);
        p = buf + PROBE_TCP_LEN;
        memcpy(p, tcpopt, tcpoptLen);
    }
    
    if (badsum) {
        srand(time(0));
        tcp->th_sum = rand() & 0xffff;
    } else {
	sum = in_checksum((uint16_t *)&srcAddr, 4);
	sum += in_checksum((uint16_t *)&dstAddr, 4);
	sum += ntohs(IPPROTO_TCP + protoLen);
	sum += in_checksum((uint16_t *)tcp, protoLen);
        tcp->th_sum = CKSUM_CARRY(sum);
#ifdef _DEBUG
	std::printf("tcp->th_sum = 0x%04x\n", ntohs(tcp->th_sum));
#endif
    }

    return tcphdrLen;
}

int TcpProbeSock::buildProtocolPacket(u_char *buf, int protoLen, u_char ttl, u_short flagFrag,
				      u_short sport, u_short dport, uint32_t seq, uint32_t ack)
{
    int iplen, tcplen;

    iplen = buildIpHeader(buf, protoLen, ttl, flagFrag);
    assert(iplen == iphdrLen);
	
    tcplen = buildProtocolHeader(buf + iplen, protoLen, sport, dport, seq, ack);
    assert(tcplen == tcphdrLen);

    return iphdrLen + protoLen;	// total packet length
}

    
