#include "ProbeRoute.hpp"
#include <assert.h>
// #include <getopt.h>

sigjmp_buf jumpbuf;
int verbose;
int protocol = IPPROTO_TCP;
int srcport;
const char *device;
int nquery = 3;
int waittime = 3;
int firstttl = 1, maxttl = 30;
int fragsize;
int mtu;
int conn;
int badsum, badlen;
const char *host, *service, *srcip;
u_char flags = TH_SYN;

int connfd = -1;
int origttl;
static void Close();

#define printOpt(x) std::cout << #x": " << x << std::endl

static void sig_int(int signo)
{
    exit(1);
}

static void printOpts()
{
    printOpt(verbose);
    printOpt(protocol);
    printOpt(srcport);
    printOpt(nullToEmpty(device));
    printOpt(nquery);
    printOpt(waittime);
    printOpt(firstttl);
    printOpt(maxttl);
    printOpt(fragsize);
    printOpt(mtu);
    printOpt(conn);
    printOpt(badsum);
    printOpt(badlen);
    printOpt(nullToEmpty(host));
    printOpt(nullToEmpty(service));
    printOpt(nullToEmpty(srcip));
    std::printf("flags: 0x%02x\n", flags);
}

int main(int argc, char *argv[])
{
    const int on = 1;
    std::string msg;
    struct linger linger;
    int i, n;
    socklen_t optlen;
    int ttl;
    const u_char *ptr;
    const struct ip *ip;
    struct sockaddr_in *sinptr;
    struct in_addr src, dst, lastrecv;
    struct timeval tv;
    double rtt;
    int caplen, len, iplen = 0, tcplen = 0, packlen;
    u_short sport, dport;
    uint16_t ipid = (u_short)time(0) & 0xffff;
    uint32_t seq = 0, ack = 0;
    u_char buf[MAX_MTU];
    u_char tcpopt[TCP_OPT_LEN], ipopt[IP_OPT_LEN];
    bool found = false, unreachable = false;
    int code = 0, tcpcode = 0;

    ProbeSock *probe;

    // make std::cout and stdout unbuffered
    std::cout.setf(std::ios::unitbuf);
    setbuf(stdout, NULL);

    if (parseOpt(argc, argv, msg) < 0) {
	if (!msg.empty())
	    std::cerr << msg << std::endl;
	std::cerr << "use -h to get help" << std::endl;
	exit(1);
    }

    printOpts();

    try {
	ProbeAddressInfo addressInfo(host, service, srcip, srcport, device, mtu);
	std::cout << addressInfo << std::endl;

        // addressInfo.getDeviceInfo();
        // addressInfo.printDeviceInfo();
        // addressInfo.freeDeviceInfo();

	sinptr = (struct sockaddr_in *)addressInfo.getLocalSockaddr();
	src = sinptr->sin_addr;
	sport = ntohs(sinptr->sin_port);

	sinptr = (struct sockaddr_in *)addressInfo.getForeignSockaddr();
	dst = sinptr->sin_addr;
	dport = ntohs(sinptr->sin_port);

	mtu = addressInfo.getDevMtu();
		

	signal(SIGINT, sig_int);

	switch (protocol) {
	case IPPROTO_TCP:
	    if (conn && !addressInfo.isSameLan()) { // no need use connect probe in the
						    // same LAN
		if ((connfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		    throw ProbeException("socket");

		// Must abort the connection immediately when it is closed, to ensure the
		// write() packet wouldn't arrive to the target host.
		linger.l_onoff = 1, linger.l_linger = 0;
		if (setsockopt(connfd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) < 0)
		    throw ProbeException("setsockopt SO_LINGER");

		if (setsockopt(connfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		    throw ProbeException("setsockopt SO_REUSEADDR");
#ifdef SO_REUSEPORT
		if (setsockopt(connfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		    throw ProbeException("setsockopt SO_REUSEPORT");
#endif
		if (bind(connfd, addressInfo.getLocalSockaddr(),
			 addressInfo.getLocalSockaddrLen()) < 0)
		    throw ProbeException("bind");

		n = TcpProbeSock::nonbConn(connfd, addressInfo.getForeignSockaddr(),
					   addressInfo.getForeignSockaddrLen(), waittime, 0);

		if (verbose > 1)
		    std::cerr << "nonbConn() returns " << n << " ("
			      << (n < 0 ? "failed" :
                                  n == 0 ? "succeed" :
                                  n == 1 ? "refused" :
                                  n == 2 ? "timed out" : "unknown state")
			      << ")" << std::endl;

		if (n == 0) {
		    // Capture the write() packet, then set the seq & ack.  To avoid
		    // the write() packet arriving to remote host, we need to set the
		    // TTL to 1.

		    ProbePcap capture(addressInfo.getDevice().c_str(), "tcp");

		    std::cerr << "register atexit\n";
		    if (atexit(Close) != 0)
			throw ProbeException("atexit");

                    optlen = sizeof(origttl);
                    if (getsockopt(connfd, IPPROTO_IP, IP_TTL, &origttl, &optlen) < 0)
                        throw ProbeException("getsockopt IP_TTL");

                    ttl = 1;
                    if (setsockopt(connfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
                        throw ProbeException("setsockopt IP_TTL");

                    if (write(connfd, "\xa5", 1) != 1)
                        throw ProbeException("write");
		    
                    // capture the write() packet immediately or when it retransmit
                    for ( ; ; ) {
                        ptr = capture.nextPcap(&caplen);
                        assert(ptr);
                        if (TcpProbeSock::capWrite(
                                ptr,
                                caplen,
                                sport,
                                dport,
                                ipid,
                                seq,
                                ack,
				ipopt,
				iplen,
				tcpopt,
				tcplen
                            ))
                            break;
                    }

                    if (verbose > 2) {
                        std::cerr << "captured ipid: " << ipid
                                  << " seq: " << seq
                                  << " ack: " << ack << std::endl;

			fprintf(stderr, "captured ipopt (%d): ", iplen);
			for (i = 0; i < iplen; i++)
			    std::fprintf(stderr, "%02x ", ipopt[i]);
			std::fprintf(stderr, "%s\n", iplen ? "" : "null");

			fprintf(stderr, "captured tcpopt (%d): ", tcplen);
			for (i = 0; i < tcplen; i++)
			    std::fprintf(stderr, "%02x ", tcpopt[i]);
			std::fprintf(stderr, "%s\n", tcplen ? "" : "null");
		    }

		    // set out-of-order sequence
		    ++ipid, ++seq;
		}
		else if (n > 0) {
		    // connection refused or timed out
		    if (verbose)
			std::cerr << "can't connect to " << host
                                  << " (" << service <<")"
                                  << std::endl;
		    close(connfd);
		    connfd = -1;
		}
		else {
                    close(connfd);
		    throw ProbeException("nonbConn");
                }
	    }

	    // 
	    // Now we can build the TCP packet
	    // 
            if (fragsize)         // don't set tcp mss options
                tcplen = 0;

	    if (badlen) {
		probe = new TcpProbeSock(
		    mtu,
		    src,
		    dst,
		    4,
		    NULL,
		    tcplen,
		    tcpopt,
		    ipid,
		    seq,
		    ack
		);
	    }
	    else {
		probe = new TcpProbeSock(
		    mtu,
		    src,
		    dst,
		    iplen,
		    ipopt,
		    tcplen,
		    tcpopt,
		    ipid,
		    seq,
		    ack
		);
	    }

	    if (verbose > 2) {
		if (TcpProbeSock *tcpProbe = dynamic_cast<TcpProbeSock *>(probe))
		    std::cout << *tcpProbe << std::endl;
		else
		    throw std::bad_cast();
	    }

	    break;                // case IPPROTO_TCP

	case IPPROTO_UDP:
	    if (badlen)
		probe = new UdpProbeSock(mtu, src, dst, 4);
	    else
		probe = new UdpProbeSock(mtu, src, dst);

	    if (verbose > 2)
		std::cout << *probe << std::endl;

	    break;		  // case IPPROTO_UDP

	case IPPROTO_ICMP:
	    if (badlen)
		probe = new IcmpProbeSock(mtu, src, dst, flags, 4);
	    else
		probe = new IcmpProbeSock(mtu, src, dst, flags);

	    if (verbose > 2) {
		if (IcmpProbeSock *icmpProbe = dynamic_cast<IcmpProbeSock *>(probe))
		    std::cout << *icmpProbe << std::endl;
		else 
		    throw std::bad_cast();
	    }

	    break;		  // case IPPROTO_ICMP
		
	default:
	    std::cerr << "unknown protocol: " << protocol << std::endl;
	    exit(1);
	} // case PROTOCOL

	//
	// Send the probe and obtain the router/host IP
	// 
        ProbePcap capture(addressInfo.getDevice().c_str(),
                          "tcp or icmp[0:1] == 3 or icmp[0:1] == 11 or icmp[0:1] == 12");

	bzero(buf, sizeof(buf));

	for (ttl = firstttl;
	     ttl < maxttl;
	     // the original traceroute(1) increments the destination UDP port 
	     ++ttl, (protocol == IPPROTO_UDP && !service) ? ++dport : 
		   ({
		       if (protocol == IPPROTO_ICMP)
			   (dynamic_cast<IcmpProbeSock *>(probe))->incrIcmpSeq();
		       dport;
		   })
	) {
            std::printf("%3d ", ttl);
	    for (i = 0; i < nquery; i++) {
		if (gettimeofday(&tv, NULL) < 0)
		    throw ProbeException("gettimeofday");

		if (protocol == IPPROTO_TCP)
		    packlen = (flags == TH_SYN) ?
			      probe->getProtocolHdrLen() :
			      probe->getPmtu() - probe->getIphdrLen();
		else
		    packlen = probe->getPmtu() - probe->getIphdrLen();

                if (fragsize)
                    probe->buildProtocolHeader(
                        buf,
                        packlen,
                        sport,
                        dport,
                        flags,
                        badsum
                    );

		if (fragsize)
		    probe->sendFragPacket(
			buf,
			packlen,
			ttl,
			fragsize,
			addressInfo.getForeignSockaddr(),
			addressInfo.getForeignSockaddrLen()
		    );

		else {
		    len = probe->buildProtocolPacket(
                        buf,
                        packlen,
                        ttl,
                        IP_DF,
                        sport,
                        dport,
                        flags,
                        badsum
                    );

		    probe->sendPacket(
                        buf,
                        len,
                        0,
                        addressInfo.getForeignSockaddr(),
                        addressInfo.getForeignSockaddrLen()
                    );
		}
                
		alarm(waittime);

		if (sigsetjmp(jumpbuf, 1) != 0) {
		    std::cout << " *";
		    alarm(0);
		    continue;
		}

		code = tcpcode = 0;

		for ( ; ; ) {
		    ptr = capture.nextPcap(&caplen);
		    assert(ptr != NULL);
		    if (code = probe->recvIcmp(ptr, caplen))
			break;
		    if (protocol == IPPROTO_TCP) {
			if (TcpProbeSock *tcpProbe = dynamic_cast<TcpProbeSock *>(probe)) {
			    if (tcpcode = tcpProbe->recvTcp(ptr, caplen, sport, dport))
				break;
			} else {
			    throw std::bad_cast();
			}
		    }
		}
		alarm(0);

		if ((rtt = delta(&tv)) < 0)
		    throw ProbeException("delta");
		ip = (struct ip *)ptr;
		if (memcmp(&ip->ip_src, &lastrecv, sizeof(struct in_addr)) ||
		    i == 0) {
                    std::printf("%s%s", i ? "\n     " : " ",
                                inet_ntoa(ip->ip_src));
		    lastrecv = ip->ip_src;
		}

		std::string s;
		std::ostringstream ss;
		if (code && code != -1) {
		    unreachable = true; // means found for UDP when ICMP code is
					// ICMP_UNREACH_PORT
		    if (code == -2)
			s = verbose ? "Bad IP length" : "!IP_HL";
		    else {
			switch (--code) {
			case 3:	  // ICMP_UNREACH_PORT
			    if (ip->ip_ttl <= 1)
				s = verbose ? "Port unreachable" : "!";
			    break;

			case 0:	  // ICMP_UNREACH_NET
			    s = verbose ? "Net unreachable" : "!N";
			    break;

			case 2:	  // ICMP_UNREACH_PROTOCOL
			    s = verbose ? "Protocol unreachable" : "!P";
			    break;

			case 4:	  // ICMP_UNREACH_NEEDFRAG
			    ss << "Need fragment (next MTU = " << probe->getPmtu() << ")";
			    s = verbose ? ss.str() : "!F";
			    break;

			case 5:	  // ICMP_UNREACH_SRCFAIL
			    s = verbose ? "Source route failed" : "!S";
			    break;

			case 6:	  // ICMP_UNREACH_NET_UNKNOWN
			    s = verbose ? "Unknown net" : "!U";
			    break;

			case 7:	  // ICMP_UNREACH_HOST_UNKNOWN
			    s = verbose ? "Unknown host" : "!W";
			    break;

			case 8:	  // ICMP_UNREACH_ISOLATED
			    s = verbose ? "Source route isolated" : "!I";
			    break;

			case 9:	  // ICMP_UNREACH_NET_PROHIB
			    s = verbose ? "Admin prohibited net" : "!A";
			    break;

			case 10:  // ICMP_UNREACH_HOST_PROHIB
			    s = verbose ? "Admin prohibited host" : "!Z";
			    break;

			case 11:  // ICMP_UNREACH_TOSNET
			    s = verbose ? "Bad tos for net" : "!Q";
			    break;

			case 12:  // ICMP_UNREACH_TOSHOST
			    s = verbose ? "Bad tos for host" : "!T";
			    break;

			case 13:  // ICMP_UNREACH_FILTER_PROHIB
			    s = verbose ? "Admin prohibited filter" : "!X";
			    break;

			case 14:  // ICMP_UNREACH_HOST_PRECEDENCE
			    s = verbose ? "Host precedence violation" : "!V";
			    break;

			case 15:  // ICMP_UNREACH_PRECEDENCE_CUTOFF
			    s = verbose ? "Precedence cutoff" : "!C";
			    break;

			default:
			    ss << " !<" << code << ">";
			    s = ss.str();
			    break;
			}
		    }
		}
			
		std::printf("%s%s  %.3f ms", s.empty() ? "" : "  ", s.c_str(), rtt);
                
		if (ip->ip_src.s_addr == dst.s_addr)
		    found = true;
	    }
	    std::cout << std::endl;

	    if (found || unreachable) {
		if (protocol == IPPROTO_TCP) {
		    if (connfd >= 0)
			std::cout << "Port " << dport << " open" << std::endl;
		    else if (conn)
			std::cout << "Port " << dport << " closed" << std::endl;
		    else {
			switch (tcpcode) {
			case 1:
			    if (flags == TH_SYN)
				std::cout << "Port " << dport << " closed" << std::endl;
			    else
				std::cout << "Port " << dport << " closed/filtered" << std::endl;
			    break;

			case 2:
			    std::cout << "Port " << dport << " open" << std::endl;
			    break;

			default:
			    ;
			}
		    }
		}
		break;
	    }
	}

    } catch (ProbeException &e) {
	std::cerr << e.what() << std::endl;
	exit(1);
    } catch (std::bad_cast &e) {
	std::cerr << e.what() << std::endl;
	exit(1);
    }

    return 0;

}
    
static void Close()
{
    if (connfd >= 0 && origttl > 0) {
	std::cerr << "connfd = " << connfd << " origttl = " << origttl << std::endl;
	// Resume the original TTL to ensure that we can discard the
	// connection successfully.
	setsockopt(connfd, IPPROTO_IP, IP_TTL, &origttl, sizeof(origttl));
	close(connfd);
    }
}
	
