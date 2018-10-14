#include "ProbeRoute.hpp"
#include <assert.h>
#include <errno.h>

static int get_distance(int ttl)
{
    
    int i = 1;
    while (i - ttl < 0)
	i *= 2;

    return i - ttl;
}

        
int ProbeSock::openSock(const int protocol) throw(ProbeException)
{
    int rawfd;
    std::stringstream msg;
    const int on = 1;
    const int size = MAX_MTU;

#if defined _LINUX || defined _CYGWIN
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


#if defined _LINUX || defined _CYGWIN
    ip->ip_len = htons(iphdrLen + protoLen);
#else
    ip->ip_len = iphdrLen + protoLen;
#endif

    // Don't change the value of ip_id. If the ip_id is 0, system will arrange a
    // random ID, so the fragment packet can't be reassembled.
    ip->ip_id = htons(ipid);
    // std::cerr << "ip_id = " << ipid << std::endl;

#if defined _LINUX || defined _CYGWIN
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


ssize_t ProbeSock::sendPacket(const void *buf, size_t buflen, int flags, const struct sockaddr *to, socklen_t tolen)
    throw(ProbeException)
{
#ifdef _CYGWIN
    if (!getenv("PROBE_RECV") && protocol == IPPROTO_TCP) {
        
        assert(Sendfp);
        assert(EtherLen > 0);

        u_char tcpbuf[MAX_MTU];
        memcpy(tcpbuf, EtherHdr, EtherLen);     // copy MAC header
        memcpy(tcpbuf + EtherLen, buf, buflen); // copy IP + TCP + Payload

        if (pcap_sendpacket(Sendfp, (const u_char *)tcpbuf, EtherLen + buflen) != 0)
            throw ProbeException("pcap_sendpacket error", pcap_geterr(Sendfp));

        return EtherLen + buflen;
    }
#endif
    ssize_t len;
    
    if ((len = sendto(rawfd, buf, buflen, flags, to, tolen)) != (ssize_t)buflen)
        throw ProbeException("sendto error");

    // std::cerr << "sendto " << len << " bytes\n";

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
            else                   // exactly the last packet
                flags = offset >> 3;
        } else {
            flags = (offset >> 3) | IP_MF;
        }

        iplen = buildIpHeader(buf, sendlen, ttl, flags);
        memcpy(buf + iplen, ptr, sendlen);
        // The ICMP data on AIX can't be less than 8 bytes, so pad at
        // least 8 bytes.
        sendPacket(buf, iplen + (sendlen < 8 ? 8 : sendlen), 0, to, tolen);
        offset += sendlen;
        remlen -= sendlen;
        ptr += sendlen;
    }

    return packlen;
}

	
int TcpProbeSock::buildProtocolHeader(
    u_char *buf,
    int protoLen,
    bool badsum
) {
    struct tcphdr *tcp;
    u_char *p;
    uint32_t sum = 0;

    assert(protoLen >= tcphdrLen);
    bzero(buf, tcphdrLen);
    tcp = (struct tcphdr *)buf;

    tcp->th_sport = htons(sport);
    tcp->th_dport = htons(dport);
    tcp->th_seq = htonl(tcpseq);
    tcp->th_ack = htonl(tcpack);
    tcp->th_x2 = 0;
    tcp->th_off = tcphdrLen >> 2;
    tcp->th_flags = tcpflags;
    tcp->th_urp = (tcpflags & TH_URG && protoLen - tcphdrLen) ?
                  htons(1) : 0;		// urgent pointer
    if (capwin)
	tcp->th_win = htons(capwin);
    else
	tcp->th_win = htons(MAX_MTU);	// default 65535
    tcp->th_sum = 0;			// calculate later

    if (tcphdrLen > PROBE_TCP_LEN) {
        assert(tcphdrLen - PROBE_TCP_LEN == tcpoptLen);
        p = buf + PROBE_TCP_LEN;
        memcpy(p, tcpopt, tcpoptLen);
    }
    
    if (badsum) {
	if (getenv("CHECKSUM_ZERO"))
	    tcp->th_sum = (u_short)0x0000 & 0xffff;
	else
	    tcp->th_sum = (u_short)Rand() & 0xffff;
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

int ProbeSock::buildProtocolPacket(
    u_char *buf,
    int protoLen,
    u_char ttl,
    u_short flagFrag,
    bool badsum
) {
    int iplen, hdrlen;

    iplen = buildIpHeader(buf, protoLen, ttl, flagFrag);
    assert(iplen == iphdrLen);
	
    hdrlen = buildProtocolHeader(buf + iplen, protoLen, badsum);
    assert(hdrlen == getProtocolHdrLen());

    return iphdrLen + protoLen;	  // total packet length
}

// Guess next MTUs
static int mtus[] = {
    65535,
    17914,
    8166,
    4464,
    4352,
    2048,
    2002,
    1536,
    1500,
    1492,
    1006,
    576,
    552,
    544,
    512,
    508,
    296,
    68,
    0
};

int ProbeSock::recvIcmp(const u_char *buf, const int len)
{
    //
    // Return:
    // 
    //   -2 - ICMP_PARAMPROB
    //   -1 - ICMP_TIMXCEED
    //    0 - Packet too short or other
    //   >0 - ICMP code + 1 (type = ICMP_UNREACH)
    //   

    const struct ip *ip, *origip;
    const struct icmp *icmp;
    u_char type, code;
    int iplen, icmplen, origiplen;
    static int *mtuptr = mtus;
    

    ip = (struct ip *)buf;
    iplen = ip->ip_hl << 2;
    if (iplen < PROBE_IP_LEN || ip->ip_p != IPPROTO_ICMP)
        return 0;

    if ((icmplen = len - iplen) < PROBE_ICMP_LEN)
        return 0;


    icmp = (struct icmp *)(buf + iplen);
    type = icmp->icmp_type;
    code = icmp->icmp_code;

    if ((type == ICMP_TIMXCEED && code == ICMP_TIMXCEED_INTRANS) ||
        type == ICMP_UNREACH || type == ICMP_PARAMPROB) {

        origip = (struct ip *)(buf + iplen + PROBE_ICMP_LEN);
        origiplen = origip->ip_hl << 2;

        if (origip->ip_p != protocol)
            return 0;
        
        // ICMP header + Original IP header + First 8 bytes of data field
        if (icmplen < PROBE_ICMP_LEN + origiplen + 8)
            return 0;
        
        if (origip->ip_dst.s_addr != dstAddr.s_addr ||
            origip->ip_id != htons(ipid))
            return 0;

        // IP header bad length
        if (type == ICMP_PARAMPROB &&
            *((u_char *)origip + 20) == 0x44)
            return -2;

        if (type == ICMP_UNREACH && code == ICMP_UNREACH_NEEDFRAG) {
#ifdef HAVE_ICMP_NEXTMTU
            pmtu = ntohs(icmp->icmp_nextmtu);
#else
            pmtu = ntohs(((struct my_pmtu *)&icmp->icmp_void)->ipm_nextmtu);
#endif
            if (pmtu) {
                for ( ; *mtuptr >= pmtu; ++mtuptr) ;
                // std::cerr << "next mtu: " << *mtuptr << std::endl;
            }
            else
                pmtu = *mtuptr++;
            
        }

	if (reverse)
	    distance = get_distance(ip->ip_ttl);
	
        return ((type == ICMP_TIMXCEED) ? -1 : code + 1);
    }

    return 0;
}
    
bool TcpProbeSock::capWrite(
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
) {
    // Return:
    //   true  - captured write()
    //   false - haven't captured
    const struct ip *ip;
    const struct tcphdr *tcp;
    int iplen, tcplen;

    ip = (struct ip *)buf;
    iplen = ip->ip_hl << 2;

    if (iplen < PROBE_IP_LEN || ip->ip_p != IPPROTO_TCP)
        return false;

    if ((tcplen = len - iplen) < PROBE_TCP_LEN)
        return false;
    
    tcp = (struct tcphdr *)(buf + iplen);
    tcplen = tcp->th_off << 2;
    if (tcplen < PROBE_TCP_LEN)
        return false;

    // obtain the write() packet after connection established
    if (
        tcp->th_sport == htons(sport) &&
        tcp->th_dport == htons(dport) &&
        tcp->th_flags & TH_PUSH
    ) {
        ipid = ntohs(ip->ip_id);
        seq = ntohl(tcp->th_seq);
        ack = ntohl(tcp->th_ack);
	capwin = ntohs(tcp->th_win);
        if ((ipoptlen = iplen - PROBE_IP_LEN) > 0) {
            memcpy(ipopt, (u_char *)ip + PROBE_IP_LEN, ipoptlen);
        }
        if ((tcpoptlen = tcplen - PROBE_TCP_LEN) > 0) {
            memcpy(tcpopt, (u_char *)tcp + PROBE_TCP_LEN, tcpoptlen);
        }
        return true;
    }

    return false;
    
}


int TcpProbeSock::recvTcp(const u_char *buf, int len)
{
    //
    // Return:
    // 
    //    0 - Packet too short or other
    //    1 - received RST packet
    //    2 - received non-RST packet
    //    

    const struct ip *ip;
    const struct tcphdr *tcp;
    int iplen, tcplen;
    
    ip = (struct ip *)buf;
    iplen = ip->ip_hl << 2;

    if (iplen < PROBE_IP_LEN || ip->ip_p != IPPROTO_TCP)
        return 0;

    if ((tcplen = len - iplen) < PROBE_TCP_LEN)
        return 0;
    
    tcp = (struct tcphdr *)(buf + iplen);
    tcplen = tcp->th_off << 2;
    if (tcplen < PROBE_TCP_LEN)
        return 0;

    // TCP RFC 793 (Page 65) 
    if (
	tcp->th_sport == htons(dport) &&
        tcp->th_dport == htons(sport) &&
        (
            // Send SYN packet when state is listen.
            ntohl(tcp->th_ack) == tcpseq + 1 ||
            // Send non-SYN packet with out-of-order SEQ or any ACK
            // when state is closed/listen.
            (ntohl(tcp->th_seq) == tcpack && tcp->th_flags & TH_RST) ||
            // Send out-of-order SEQ when state is established.
            (ntohl(tcp->th_ack) == tcpseq - 1) ||
            // Send order SEQ when state is established.
	    (ntohl(tcp->th_ack) == tcpseq + pmtu - ipoptLen - tcpoptLen - 40) ||
	    // TCP Keep-Alive or ACK (Maybe DUP ACK)
            ntohl(tcp->th_ack) >= tcpseq
        )
    )
	{
	    if (reverse) {
		hostreach = true;
		distance = get_distance(ip->ip_ttl);
	    }
	    
	    return (tcp->th_flags & TH_RST) ? 1 : 2;
	}

    return 0;
}


int TcpProbeSock::nonbConn(int fd, const struct sockaddr *addr, socklen_t addrlen,
                           int nsec, unsigned long msec)
{
    /* Return
       -1: failed
       0: success
       1: connection refused
       2: connection timed out
    */

    int flags;
    int n;
    int error;
    socklen_t len;
    fd_set rset, wset;
    struct timeval tv;

    if ((flags = fcntl(fd, F_GETFL, 0)) < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    error = 0;
    if ((n = connect(fd, addr, addrlen)) < 0 &&
        errno != EINPROGRESS)
        return -1;              // host is down, no route to host, etc.

    if (n == 0)
        goto done;              // connect completed immediately

    FD_ZERO(&rset);
    FD_SET(fd, &rset);
    wset = rset;
    tv.tv_sec = nsec;
    tv.tv_usec = msec * 1000;

    if (select(fd + 1, &rset, &wset, NULL,
               (nsec || msec) ? &tv : NULL) == 0) {
        errno = ETIMEDOUT;
        return 2;
    }

    if (FD_ISSET(fd, &rset) || FD_ISSET(fd, &wset)) {
        len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            return (errno == ECONNREFUSED) ? 1 : -1; // Solaris pending error
        }
    } else {
        return -1;                                   // socket fd not set
    }
    
  done:
    /* restore file status flags */
    if (fcntl(fd, F_SETFL, flags) < 0)
        return -1;
	
    if (error) {
        errno = error;
        return (errno == ECONNREFUSED) ? 1 : -1;
    }
	
    return 0;                   // connection established
}


int UdpProbeSock::buildProtocolHeader(
    u_char *buf,
    int protoLen,
    bool badsum
) {
    struct udphdr *udp;
    uint32_t sum = 0;

    assert(protoLen >= PROBE_UDP_LEN);
    bzero(buf, PROBE_UDP_LEN);
    udp = (struct udphdr *)buf;

    udp->uh_sport = htons(sport);
    udp->uh_dport = htons(dport);
    udp->uh_ulen = htons(protoLen);
    udp->uh_sum = 0;              // calculate later

    if (badsum) {
	if (getenv("CHECKSUM_ZERO"))
	    udp->uh_sum = (u_short)0x0000 & 0xffff;
	else
	    udp->uh_sum = (u_short)Rand() & 0xffff;
    } else {
        sum = in_checksum((uint16_t *)&srcAddr, 4);
        sum += in_checksum((uint16_t *)&dstAddr, 4);
        sum += ntohs(IPPROTO_UDP + protoLen);
        sum += in_checksum((uint16_t *)udp, protoLen);
        udp->uh_sum = CKSUM_CARRY(sum);
    }

    return PROBE_UDP_LEN;
}

int IcmpProbeSock::buildProtocolHeader(
    u_char *buf,
    int protoLen,
    bool badsum
) {
    struct icmp *icmp;
    uint32_t sum = 0;
    struct timeval tvorig;
    uint32_t tsorig;

    assert(protoLen >= icmphdrLen);
    bzero(buf, icmphdrLen);
    icmp = (struct icmp *)buf;

    icmp->icmp_type = icmpType;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;	  // calculate later
    icmp->icmp_id = htons(icmpId);
    icmp->icmp_seq = htons(icmpSeq);

    if (icmpType == ICMP_TSTAMP ||
        icmpType == ICMP_TSTAMPREPLY
    ) {
        if (gettimeofday(&tvorig, (struct timezone *)NULL) < 0) {
            perror("gettimeofday");
            exit(1);
        }
        tsorig = tvorig.tv_sec % (24 * 60 * 60) * 1000 + tvorig.tv_usec / 1000;
        icmp->icmp_otime = htonl(tsorig);

        if (icmpType == ICMP_TSTAMP)
            icmp->icmp_rtime = icmp->icmp_ttime = 0;
        else
            icmp->icmp_rtime = icmp->icmp_ttime = icmp->icmp_otime;
    }

    if (badsum) {
	if (getenv("CHECKSUM_ZERO"))
	    icmp->icmp_cksum = (u_short)0x0000 & 0xffff;
	else
	    icmp->icmp_cksum = (u_short)Rand() & 0xffff;
    } else {
        sum = in_checksum((uint16_t *)icmp, protoLen);
        icmp->icmp_cksum = CKSUM_CARRY(sum);
    }

    return icmphdrLen;
}

int IcmpProbeSock::recvIcmp(const u_char *buf, const int len)
{
    //
    // Return:
    //
    //   -3 - ICMP echo or timestamp reply
    //   -2 - ICMP_PARAMPROB
    //   -1 - ICMP_TIMXCEED
    //    0 - Packet too short or other
    //   >0 - ICMP code + 1 (type = ICMP_UNREACH)
    //   

    const struct ip *ip, *origip;
    const struct icmp *icmp;
    u_char type, code;
    int iplen, icmplen, origiplen;
    static int *mtuptr = mtus;
    

    ip = (struct ip *)buf;

    // std::printf("src: %s, ", inet_ntoa(ip->ip_src));
    // std::printf("dst: %s\n", inet_ntoa(ip->ip_dst));
    // std::printf("protocol: %d\n", ip->ip_p);

    iplen = ip->ip_hl << 2;
    // std::cout << "iplen: " << iplen << std::endl;
    // std::cout << "protocol offset: " << offsetof(struct ip, ip_p) << std::endl;
    // std::printf("protocol: %d\n", ip->ip_p);
    // std::printf("ICMP protocol: %d\n", IPPROTO_ICMP);
    // std::cout << "icmplen: " << len - iplen << std::endl;
    if (iplen < PROBE_IP_LEN || ip->ip_p != IPPROTO_ICMP)
        return 0;

    if ((icmplen = len - iplen) < PROBE_ICMP_LEN)
        return 0;

    // std::printf("ICMP src: %s, dst: %s\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

    std::printf("ICMP src: %s, ", inet_ntoa(ip->ip_src));
    std::printf("dst: %s\n", inet_ntoa(ip->ip_dst));

    icmp = (struct icmp *)(buf + iplen);
    type = icmp->icmp_type;
    code = icmp->icmp_code;

    if (type == ICMP_ECHOREPLY ||
        type == ICMP_TSTAMPREPLY) {

        if (icmp->icmp_id == htons(icmpId) &&
            icmp->icmp_seq == htons(icmpSeq) &&
            ip->ip_id != htons(ipid)) // ensure the message is not sent by ourselves
            return -3;

    }

    else if ((type == ICMP_TIMXCEED && code == ICMP_TIMXCEED_INTRANS) ||
             type == ICMP_UNREACH ||
             type == ICMP_PARAMPROB) {

        origip = (struct ip *)(buf + iplen + PROBE_ICMP_LEN);
        origiplen = origip->ip_hl << 2;

        if (origip->ip_p != IPPROTO_ICMP)
            return 0;

        // ICMP header + Original IP header + First 8 bytes of data field
        if (icmplen < PROBE_ICMP_LEN + origiplen + 8)
            return 0;
        
        if (origip->ip_dst.s_addr != dstAddr.s_addr ||
            origip->ip_id != htons(ipid))
            return 0;

        // IP header bad length
        if (type == ICMP_PARAMPROB &&
            *((u_char *)origip + 20) == 0x44)
            return -2;

        if (type == ICMP_UNREACH && code == ICMP_UNREACH_NEEDFRAG) {
#ifdef HAVE_ICMP_NEXTMTU
            pmtu = ntohs(icmp->icmp_nextmtu);
#else
            pmtu = ntohs(((struct my_pmtu *)&icmp->icmp_void)->ipm_nextmtu);
#endif
            if (pmtu) {
                for ( ; *mtuptr >= pmtu; ++mtuptr) ;
                // std::cerr << "next mtu: " << *mtuptr << std::endl;
            }
            else
                pmtu = *mtuptr++;
            
        }
        return ((type == ICMP_TIMXCEED) ? -1 : code + 1);
    }

    // printf("ICMP_TIMXCEED = %d, ICMP_TIMXCEED_INTRANS = %d\n", ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS);
    
    printf("type = %d, code = %d\n", type, code);
    
    return 0;
}
 
int UdpProbeSock::recvIcmp(const u_char *buf, const int len)
{
    //
    // Return:
    // 
    //   -2 - ICMP_PARAMPROB
    //   -1 - ICMP_TIMXCEED
    //    0 - Packet too short or other
    //   >0 - ICMP code + 1 (type = ICMP_UNREACH)
    //   

    const struct ip *ip, *origip;
    const struct icmp *icmp;
    u_char type, code;
    int iplen, icmplen, origiplen;
    static int *mtuptr = mtus;
    

    ip = (struct ip *)buf;
    std::printf("src: %s, ", inet_ntoa(ip->ip_src));
    std::printf("dst: %s\n", inet_ntoa(ip->ip_dst));
    std::printf("protocol: %d\n", ip->ip_p);

    iplen = ip->ip_hl << 2;
    if (iplen < PROBE_IP_LEN || ip->ip_p != IPPROTO_ICMP)
        return 0;

    if ((icmplen = len - iplen) < PROBE_ICMP_LEN)
        return 0;


    icmp = (struct icmp *)(buf + iplen);
    type = icmp->icmp_type;
    code = icmp->icmp_code;

    if ((type == ICMP_TIMXCEED && code == ICMP_TIMXCEED_INTRANS) ||
        type == ICMP_UNREACH || type == ICMP_PARAMPROB) {

        origip = (struct ip *)(buf + iplen + PROBE_ICMP_LEN);
        origiplen = origip->ip_hl << 2;

        // ICMP header + Original IP header + First 8 bytes of data field
        if (icmplen < PROBE_ICMP_LEN + origiplen + 8)
            return 0;
        
        // Some system don't fill the original ip id correctly, so check the
        // original source/destination port instead of checking ip id.
        if (origip->ip_dst.s_addr != dstAddr.s_addr ||
            origip->ip_p != IPPROTO_UDP)
            return 0;

        const struct udphdr *udp;
        udp = (struct udphdr *)((u_char *)origip + origiplen);
        if (udp->uh_sport != htons(sport) ||
            udp->uh_dport != htons(dport))
            return 0;

        // IP header bad length
        if (type == ICMP_PARAMPROB &&
            *((u_char *)origip + 20) == 0x44)
            return -2;

        // Need fragment
        if (type == ICMP_UNREACH && code == ICMP_UNREACH_NEEDFRAG) {
#ifdef HAVE_ICMP_NEXTMTU
            pmtu = ntohs(icmp->icmp_nextmtu);
#else
            pmtu = ntohs(((struct my_pmtu *)&icmp->icmp_void)->ipm_nextmtu);
#endif
            if (pmtu) {
                for ( ; *mtuptr >= pmtu; ++mtuptr) ;
                // std::cerr << "next mtu: " << *mtuptr << std::endl;
            }
            else
                pmtu = *mtuptr++;
            
        }

	if (reverse)
	    distance = get_distance(ip->ip_ttl);

        return ((type == ICMP_TIMXCEED) ? -1 : code + 1);
    }

    return 0;
}


int setAddrByName(const char *host, struct in_addr *addr)
{

    struct addrinfo hints, *res;
    struct sockaddr_in *inaddr;

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;

    if (getaddrinfo(host, NULL, &hints, &res) != 0)
        return -1;

    inaddr = (struct sockaddr_in *)res->ai_addr;
    memmove(addr, &inaddr->sin_addr, sizeof(struct in_addr));

    return 0;
}

