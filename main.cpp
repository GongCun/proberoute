#include "ProbeRoute.hpp"
#include <assert.h>
#ifdef _CYGWIN
#include <sys/wait.h>
#include <sys/mman.h>
#include <signal.h>
#endif

sigjmp_buf jumpbuf;
int verbose;
int srcport;
const char *device;
int nquery = 3;
int waittime = 3;
int firstttl = 1, maxttl = 30;
int distance;
int fragsize;
int mtu;
int conn;
int badsum, badlen;
const char *host, *service, *srcip;
// u_char tcpFlags = TH_SYN;
u_char tcpFlags = 0;
bool tcpIsNull = false;
u_char icmpFlags = ICMP_ECHO;
std::vector<int> protoVec;
std::string captureFunc = "unknown capture";

int connfd = -1;
int origttl;
static void Close();

u_char tcpopt[TCP_OPT_LEN], ipopt[IP_OPT_LEN];
u_char *optptr;

struct sockaddr *Netmask;

#ifdef _CYGWIN
const u_char EtherLen = 14;
u_char EtherHdr[64];
pcap_t *Sendfp = NULL;
#endif
bool listDevice = false;
bool simulate = false;
bool reverse = false;
bool havereach = false;
bool hostreach = false;
bool interact = false;
uint16_t capwin = 0;
bool do_retransmit = false;
uint32_t retransmit = UINT_MAX;
long long int recvfd = -1;
struct sockaddr *GlobalLocalAddr;

#define printOpt(x) std::cout << #x": " << x << std::endl
#define printOptStr(x) std::cout << #x": " << nullToEmpty(x) << std::endl

static void sig_exit(int signo)
{
    Close();
    exit(1);
}

static void printProto()
{
    for (std::vector<int>::size_type i = 0; i != protoVec.size(); ++i) {
        if (i != 0)
            std::cout << ' ';
                         
        switch (protoVec[i]) {
        case IPPROTO_TCP:
            std::cout << "TCP";
            break;
        case IPPROTO_UDP:
            std::cout << "UDP";
            break;
        case IPPROTO_ICMP:
            std::cout << "ICMP";
            break;
        default:
            std::cout << "unknown";
            break;
        }
    }
}
 

static void printOpts()
{
    std::string s;
    std::cout << ">>>> Parse Options <<<<" << std::endl;
    
    printOpt(verbose);
    // printOpt(protocol);
    std::cout << "protocol: ";
    printProto();
    std::cout << std::endl;
	    
    if (getenv("PROBE_RECV"))
        captureFunc = "recv()";
    else
        captureFunc = "pcap()";
    printOpt(captureFunc);

    printOpt(srcport);
    printOptStr(device);
    printOpt(nquery);
    printOpt(waittime);
    printOpt(firstttl);
    printOpt(maxttl);
    printOpt(fragsize);
    printOpt(mtu);
    printOpt(conn);
    printOpt(badsum);
    printOpt(badlen);
    printOptStr(host);
    printOptStr(service);
    printOptStr(srcip);

    // TCP Flags (UAPRSF)
    std::cout << "tcpFlags: ";
    for (int i = 5; i >= 0; i--)
        std::cout << ((tcpFlags >> i) & 1);
    std::cout << std::endl;

    std::printf("icmpFlags: %d\n", icmpFlags);
    
    std::cout << ">>>> End <<<<" << std::endl;
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
    struct timeval tv, tcp_now;
    double rtt;
    int caplen, len, iplen = 0, tcplen = 0, packlen;
    u_short sport, dport;
    uint16_t ipid = (u_short)Rand() & 0xffff;
    uint32_t seq = 0, ack = 0;
    int count = 0;
    u_char buf[MAX_MTU];
    bool found = false, unreachable = false;
    int code = 0, tcpcode = 0;

    int phyDstLen, phySrcLen;	// Mac Address Length of destination and source.
    int savecode = 0;

    static ProbePcap *capture;

    std::vector<ProbeSock *> probeVec;
    std::vector<ProbeSock *>::iterator probe;

    // make std::cout and stdout unbuffered
    std::cout.setf(std::ios::unitbuf);
    setbuf(stdout, NULL);

    bzero(buf, sizeof(buf));

    if (parseOpt(argc, argv, msg) < 0) {
        if (!msg.empty())
            std::cerr << msg << std::endl;
        std::cerr << "use -h to get help" << std::endl;
        exit(1);
    }

    if (verbose > 2)
        printOpts();

    try {

        if (listDevice) {
            ProbeAddressInfo::getDeviceInfo();
            ProbeAddressInfo::listDeviceInfo();
            ProbeAddressInfo::freeDeviceInfo();
            exit(0);
        }

        ProbeAddressInfo addressInfo(host, service, srcip, srcport, device, mtu);
        if (verbose > 2)
            std::cout << addressInfo << std::endl;
        GlobalLocalAddr = addressInfo.getLocalSockaddr();

        if (getenv("PROBE_RECV")) {
#ifdef _CYGWIN
            // Cygwin _DOESN'T_ support receive data from raw socket, must use
            // original Winsock. With Winsock, a raw socket can be used with the
            // SIO_RCVALL IOCTL to receive all IP packets through a network
            // interface, the protocol must be set to IPPROTO_IP.
            recvfd = win_rawsock(addressInfo.getLocalSockaddr(),
                                 (int)addressInfo.getLocalSockaddrLen());
            if (recvfd < 0)
                throw ProbeException("win_rawsock error", MSG);

#else
            if ((recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
                throw ProbeException("socket error");
#endif
        }


#ifdef _CYGWIN
        // Since the OS after Windows XP can't send TCP raw data directly, we use
        // the WinPcap to work around it (use pcap_sendpacket() function), but
        // must get the destination and source ethernet address first.

        // Fill the gatewayMac + localMac + IPtype, check whether in
        // the same sub-network later.
        phyDstLen = getmac(
            addressInfo.getGateway(),
            EtherHdr
        );
        if (phyDstLen != 6)
            throw ProbeException("No support for PPP/VPN connection", MSG);

        char *p = (char *)addressInfo.getDevice().c_str();
        while (*p && *p != '{') // Windows device name begin from brace
            ++p;
	
        phySrcLen = getmacByDevice(p, EtherHdr + phyDstLen);
        if (phySrcLen != 6)
            throw ProbeException("No support for PPP/VPN connection", MSG);
	
        // IPv4 type is 0x0800 (IPv6 is 0x86DD, ARP is 0x0806, RARP is
        // 0x8035, and IEEE 802.1Q tag is 0x8100), we only support the
        // IPv4 now.
        p = (char *)EtherHdr + phyDstLen + phySrcLen;
        *p++ = 0x08;
        *p = 0x00;
#endif

        sinptr = (struct sockaddr_in *)addressInfo.getLocalSockaddr();
        src = sinptr->sin_addr;
        sport = ntohs(sinptr->sin_port);

        sinptr = (struct sockaddr_in *)addressInfo.getForeignSockaddr();
        dst = sinptr->sin_addr;
        dport = ntohs(sinptr->sin_port);

#ifdef _CYGWIN
        // If the destination in the same sub-network, change the MAC
        // address of gateway to destination host (not found is OK).
        if (getmac(inet_ntoa(sinptr->sin_addr), EtherHdr) == -2)
            throw ProbeException("getmac error", MSG);

        if (verbose > 2) {
            std::cerr << "Ethernet Frame:\n";
            for (int i = 0; i < 14; i++)
                std::fprintf(stderr, "%02x ", EtherHdr[i]);
            std::putc('\n', stderr);
        }

        char errbuf[PCAP_ERRBUF_SIZE];
        if (!getenv("PROBE_RECV")) {
            if ((Sendfp = pcap_open(
                     addressInfo.getDevice().c_str(),
                     CAP_LEN,
                     PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
                     1,                         // no timeout (ms)
                     NULL,                      // authentication on the remote machine
                     errbuf)) == NULL
            )
                throw ProbeException("pcap_open", errbuf);
        }

#endif

        if ((mtu = addressInfo.getDevMtu()) <= 0) {
            std::ostringstream ss;
            ss << "MTU size " << mtu << " error";
            throw ProbeException(ss.str());
        }

        // Set the Loose Source Route Record
        if (optptr) {
            n = (optptr - ipopt) / 4 - 1;
            // std::cerr << "n = " << n << std::endl;
            if (++n > MAX_GATEWAY + 1)
                throw ProbeException("too many source routes");
	    
            // destination at end
            memcpy((struct in_addr *)optptr,
                   &dst,
                   sizeof(struct in_addr));

            ipopt[2] = 3 + n * 4;    // option length
            iplen = ipopt[2] + 1;    // add 1 byte of NOP

            if (verbose > 2) {
                std::printf("SSR option: code = %d, len = %d, ptr = %d\n"
                            "SSR list: ",
                            ipopt[1], ipopt[2], ipopt[3]);
                for (u_char *ptr = ipopt + 4;
                     ptr <= optptr;
                     ptr += sizeof(struct in_addr))
                    std::printf("%s%s", inet_ntoa(*(struct in_addr *)ptr),
                                ptr != optptr ? " " : "\n");
            }
        }

		
        static const int signo[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM };
	
        for (i = 0; i < (int)(sizeof(signo) / sizeof(int)); i++)
            if (signal(signo[i], sig_exit) == SIG_ERR)
                throw ProbeException("signal");

        if (atexit(Close) != 0)
            throw ProbeException("atexit");

        bool haveTcp = false;
        for (std::vector<int>::size_type idx = 0; idx != protoVec.size(); ++idx)
            if (protoVec[idx] == IPPROTO_TCP) {
                haveTcp = true;
                break;
            }

        for (std::vector<int>::size_type idx = 0; idx != protoVec.size(); ++idx) {
            switch (int protocol = protoVec[idx]) {
            case IPPROTO_TCP:
                if (conn && !addressInfo.isSameLan()) {
                    // No need use connect probe in the same LAN.
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
                    if (setsockopt(connfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0)
                        throw ProbeException("setsockopt SO_REUSEPORT");
#endif

		    if (reverse) {
			ttl = maxttl;
			if (setsockopt(connfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
			    throw ProbeException("setsockopt IP_TTL");
		    }
		    
                    // Bind local address and specified port
                    if (bind(connfd, addressInfo.getLocalSockaddr(),
                             addressInfo.getLocalSockaddrLen()) < 0)
                        throw ProbeException("bind");

                    n = TcpProbeSock::nonbConn(
                        connfd,
                        addressInfo.getForeignSockaddr(),
                        addressInfo.getForeignSockaddrLen(),
                        waittime,
                        0
                    );

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

                        capture = ProbePcap::Instance(addressInfo.getDevice().c_str(), "tcp");

                        optlen = sizeof(origttl);
                        if (getsockopt(connfd, IPPROTO_IP, IP_TTL, &origttl, &optlen) < 0)
                            throw ProbeException("getsockopt IP_TTL");

			if (!simulate) {
			    ttl = 1;
			    if (setsockopt(connfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
				throw ProbeException("setsockopt IP_TTL");
			}

			// capture the write() packet immediately or when it retransmit
			if (write(connfd, "\x00", 1) != 1)
			    throw ProbeException("write");

                        for ( ; ; ) {
                            ptr = capture->nextPcap(&caplen);
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


			if (gettimeofday(&tcp_now, NULL) < 0)
			    throw ProbeException("gettimeofday");

			if (interact) {
			    std::string readline;

			    if (verbose > 2) {
				std::cerr << "first captured ipid: " << ipid
					  << " seq: " << seq
					  << " ack: " << ack << std::endl;
			    }

			    std::cout << std::endl;
			    std::cout << "Interactive mode, press Ctrl-D to end" << std::endl;

			    while (std::getline(std::cin, readline)) {
				if (write(connfd, "\x00", 1) != 1)
				    throw ProbeException("write");
				count++;
				std::printf("<sent the %d%s packet>\n", count,
					    count == 1 ? "st" :
					    count == 2 ? "nd" :
					    count == 3 ? "rd" : "th");
			    }
			    std::cin.clear();

			    if (do_retransmit) {
				std::cout << "\nPlease enter the packet# to retransmit: ";
				std::cin >> retransmit;
			    }

			} // end of interact

			if (do_retransmit) {
			    if (retransmit > count)
				retransmit = count;
			    seq += retransmit;

			    if (verbose > 2)
				std::cerr << "\nretransmit seq#: " << seq << std::endl;
			}
			else {
			    // set order byte sequence
			    ++ipid, seq += count + 1;
			}

                        if (verbose > 2) {
                            std::cerr << "captured ipid: " << ipid
                                      << " set seq: " << seq
                                      << " ack: " << ack << std::endl;

                            fprintf(stderr, "captured ipopt (%d): ", iplen);
                            for (i = 0; i < iplen; i++)
                                std::fprintf(stderr, "%02x ", ipopt[i]);
                            std::fprintf(stderr, "%s\n", iplen ? "" : "null");

                            fprintf(stderr, "captured tcpopt (%d): ", tcplen);
                            for (i = 0; i < tcplen; i++)
                                std::fprintf(stderr, "%02x ", tcpopt[i]);
                            std::fprintf(stderr, "%s\n", tcplen ? "" : "null");

                        } // verbose

			if (tcplen == 12 && ntohs(tcpopt[2]) == 8) {
			    uint32_t *p;
			    p = (uint32_t *)(tcpopt + 4);
			    if (verbose > 2)
				std::fprintf(stderr, "TSval(original): %ld\n", ntohl(*p));

			    // The timestamp increases by 1 per 500 ms.
			    uint32_t tsval = htonl(ntohl(*p) + delta(&tcp_now) / 500);
			    memcpy(tcpopt + 4, (u_char *)&tsval, 4);
			    p = (uint32_t *)(tcpopt + 4);
			    if (verbose > 2)
				std::fprintf(stderr, "TSval(changed): %ld\n", ntohl(*p));
				
			    p = (uint32_t *)(tcpopt + 8);
			    if (verbose > 2)
				std::fprintf(stderr, "TSecr: %ld\n", ntohl(*p));
			} // set TSval
                    }	  // nonbConn succeed
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
                if (fragsize)   // don't set tcp mss options
                    tcplen = 0;

                ProbeSock *tcpProbe;
                if (badlen)
                    tcpProbe = new TcpProbeSock(
                        mtu,
                        src,
                        dst,
                        sport,
                        dport,
                        4,
                        NULL,
                        tcplen,
                        tcpopt,
                        ipid,
                        seq,
                        ack,
                        tcpFlags
                    );
                else
                    tcpProbe = new TcpProbeSock(
                        mtu,
                        src,
                        dst,
                        sport,
                        dport,
                        iplen,
                        ipopt,
                        tcplen,
                        tcpopt,
                        ipid,
                        seq,
                        ack,
                        tcpFlags
                    );

                probeVec.push_back(tcpProbe);

                break;          // case IPPROTO_TCP

            case IPPROTO_UDP:

                UdpProbeSock *udpProbe;

                if (badlen)
                    udpProbe = new UdpProbeSock(
                        // default packet size used in traceroute is 52 bytes
                        protoVec.size() == 1 ? mtu : 52,
                        src,
                        dst,
                        sport,
                        // base port number used in traceroute
                        haveTcp ? 33434 : dport,
                        4
                    );
                else
                    udpProbe = new UdpProbeSock(
                        // default packet size used in traceroute is 52 bytes
                        protoVec.size() == 1 ? mtu : 52,
                        src,
                        dst,
                        sport,
                        // classic base port number used in traceroute
                        haveTcp ? 33434 : dport,
                        iplen,
                        ipopt
                    );

                probeVec.push_back(udpProbe);

                break;		  // case IPPROTO_UDP

            case IPPROTO_ICMP:

                IcmpProbeSock *icmpProbe;
                
                if (badlen)
                    icmpProbe = new IcmpProbeSock(
                        mtu,
                        src,
                        dst,
                        icmpFlags,
                        4
                    );
                else
                    icmpProbe = new IcmpProbeSock(
                        mtu,
                        src,
                        dst,
                        icmpFlags,
                        iplen,
                        ipopt
                    );

                probeVec.push_back(icmpProbe);

                break;		  // case IPPROTO_ICMP
            default:
                std::cerr << "unknown protocol: " << protocol << std::endl;
                exit(1);
            } // case PROTOCOL
        }

        if (verbose > 1) {
            for (probe = probeVec.begin(); probe != probeVec.end(); ++probe) {
                std::cout << ">>>> ProbeSock <<<<" << std::endl;
                switch ((*probe)->getProtocol()) {
                case IPPROTO_TCP:
                    if (TcpProbeSock *tcpProbe = dynamic_cast<TcpProbeSock *>(*probe))
                        std::cout << *tcpProbe << std::endl;
                    else
                        throw std::bad_cast();
                    break;

                case IPPROTO_UDP:
                    if (UdpProbeSock *udpProbe = dynamic_cast<UdpProbeSock *>(*probe))
                        std::cout << *udpProbe << std::endl;
                    else
                        throw std::bad_cast();
                    break;

                case IPPROTO_ICMP:
                    if (IcmpProbeSock *icmpProbe = dynamic_cast<IcmpProbeSock *>(*probe))
                        std::cout << *icmpProbe << std::endl;
                    else 
                        throw std::bad_cast();
                    break;
                }
            }
        }

        std::cout << "proberoute to " << host
                  << " (" << inet_ntoa(dst) << ")";
        std::cout << " from " << inet_ntoa(src)
                  << " (" << addressInfo.getDevice() << ")"
                  << " with ";
        printProto();
        std::cout << " protocol" << std::endl;

        std::cout << "destination: " << addressInfo.getDestination() << ", "
                  << "gateway: " << addressInfo.getGateway();
        if (addressInfo.getDestinationMask()[0] != 0)
            std::cout << ", mask: " << addressInfo.getDestinationMask();
        std::cout << std::endl;
	
        std::cout << firstttl << " hops min, " << maxttl << " hops max" << std::endl;
        std::cout << "outgoing MTU = " << mtu << std::endl;

        //
        // Send the probe and obtain the router/host IP
        // 
        ProbePcap::resetInstance();
        capture = ProbePcap::Instance(addressInfo.getDevice().c_str(),
                                      "tcp or "
                                      "icmp[0:1] == 0  or "  // Echo Reply
                                      "icmp[0:1] == 3  or "  // Destination Unreachable
                                      "icmp[0:1] == 11 or "  // Time Exceed
                                      "icmp[0:1] == 12 or "  // Parameter Problem
                                      "icmp[0:1] == 14"      // Timestamp Reply
        );

        // bzero(buf, sizeof(buf));

        mtu = addressInfo.getDevMtu();
        for (
	    distance = maxttl,
	    ttl = (reverse ? maxttl : firstttl);
	    reverse ? (ttl >= firstttl) : (ttl <= maxttl); 
            (reverse ? --ttl : ++ttl),
		  ({
		      for (probe = probeVec.begin(); probe != probeVec.end(); ++probe)
			  ++(**probe);
		  })
	) {
	    if (hostreach)
		havereach = true;

	    while (ttl > distance)
		--ttl;
            
            std::printf("%3d ", ttl);
            for (i = 0; i < nquery; i++) {
                if (gettimeofday(&tv, NULL) < 0)
                    throw ProbeException("gettimeofday");

                // Since some probe's mtu may be updated, should synchronize to
                // all probes except the UDP default packet size (52-byte).

                for (probe = probeVec.begin(); probe != probeVec.end(); ++probe) {
                    if ((*probe)->getProtocol() == IPPROTO_UDP && protoVec.size() != 1)
                        continue;
                    if (mtu > (*probe)->getPmtu())
                        mtu = (*probe)->getPmtu();
                }
                
                for (probe = probeVec.begin(); probe != probeVec.end(); ++probe) {
                    if ((*probe)->getProtocol() == IPPROTO_UDP && protoVec.size() != 1)
                        continue;
                    if (mtu < (*probe)->getPmtu())
                        (*probe)->setPmtu(mtu);
                }

                for (probe = probeVec.begin(); probe != probeVec.end(); ++probe) {
                    int protocol = (*probe)->getProtocol();

                    if ((protocol == IPPROTO_TCP && tcpFlags == TH_SYN) ||
                        (protocol == IPPROTO_ICMP &&
                         (icmpFlags == ICMP_TSTAMP || icmpFlags == ICMP_TSTAMPREPLY)))
                        packlen = (*probe)->getProtocolHdrLen();
                    else
                        packlen = (*probe)->getPmtu() - (*probe)->getIphdrLen();
                    // packlen = mtu - (*probe)->getIphdrLen();

                    if (packlen < (*probe)->getProtocolHdrLen())
                        throw ProbeException("packet length too short", MSG);

                    if (fragsize) {
                        (*probe)->buildProtocolHeader(
                            buf,
                            packlen,
                            badsum
                        );

                        (*probe)->sendFragPacket(
                            buf,
                            packlen,
                            ttl,
                            fragsize,
                            addressInfo.getForeignSockaddr(),
                            addressInfo.getForeignSockaddrLen()
                        );
                    }
                    else {
                        len = (*probe)->buildProtocolPacket(
                            buf,
                            packlen,
                            ttl,
                            IP_DF,
                            badsum
                        );

                        (*probe)->sendPacket(
                            buf,
                            len,
                            0,
                            addressInfo.getForeignSockaddr(),
                            addressInfo.getForeignSockaddrLen()
                        );
                    }
                }
                
                
                alarm(waittime);

                if (sigsetjmp(jumpbuf, 1) != 0) {
                    std::cout << " *";
                    alarm(0);
                    continue;
                }

                code = tcpcode = 0;

                msg = "";
                for ( ; ; ) {
                    ptr = capture->nextPcap(&caplen);
                    assert(ptr != NULL);
                    // std::cerr << "!! caplen = " << caplen << std::endl;
		    
                    for (probe = probeVec.begin(); probe != probeVec.end(); ++probe) {
                        
                        if (code = (*probe)->recvIcmp(ptr, caplen)) {
                            msg = (*probe)->getProtocol() == IPPROTO_TCP ? "TCP" :
                                  (*probe)->getProtocol() == IPPROTO_UDP ? "UDP" :
                                  (*probe)->getProtocol() == IPPROTO_ICMP ? "ICMP" : "unknown";
                            goto endWait;
                        }
                            
                        
			if (!havereach) {
                        if ((*probe)->getProtocol() == IPPROTO_TCP) {
                            if (TcpProbeSock *tcpProbe = dynamic_cast<TcpProbeSock *>(*probe)) {
                                if (tcpcode = tcpProbe->recvTcp(ptr, caplen)) {
                                    savecode = tcpcode;
                                    msg = "TCP";
                                    goto endWait;
                                }
                            } else {
                                throw std::bad_cast();
                            }
                        }
			}
			
                    }
                }
              endWait:
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
                if (code && code != -1 && code != -3) {
                    unreachable = true; // means found for UDP when ICMP code is
                    // ICMP_UNREACH_PORT
                    if (code == -2)
                        s = verbose ? "Bad IP length" : "!IP_HL";
                    else {
                        switch (--code) {
                        case 0:	  // ICMP_UNREACH_NET
                            s = verbose ? "Network unreachable" : "!N";
                            break;

                        case 1:	  // ICMP_UNREACH_HOST
                            s = verbose ? "Host unreachable" : "!H";
                            break;

                        case 2:	  // ICMP_UNREACH_PROTOCOL
                            s = verbose ? "Protocol unreachable" : "!P";
                            break;

                        case 3:	  // ICMP_UNREACH_PORT
                            // FIX ME:
                            //   
                            //   The classic traceroute prints a "!" after the
                            //   time if the ttl is <= 1 since the obsoleted
                            //   router will use the ttl from the arriving probe
                            //   datagram as the ttl in its ICMP reply. So we
                            //   should probe with a ttl that's at least twice
                            //   the path length. (BUT this situation is rarely
                            //   seen.)
                            if (ip->ip_ttl <= 1)
                                s = verbose ? "Port unreachable" : "!";
                            else {
                                struct ip *origip = (struct ip *)(
                                    (char *)ip + (ip->ip_hl << 2) + PROBE_ICMP_LEN
                                );
                                if (origip->ip_p != IPPROTO_UDP) {
                                    s = verbose ? "Port unreachable" : "!PORT";
                                }
                            }
                            break;

                        case 4:	  // ICMP_UNREACH_NEEDFRAG
                            ss << "Need fragment (next MTU = " << (*probe)->getPmtu() << ")";
                            s = verbose ? ss.str() : "!F";
                            unreachable = false;
                            break;

                        case 5:	  // ICMP_UNREACH_SRCFAIL
                            s = verbose ? "Source route failed" : "!S";
                            break;

                        case 6:	  // ICMP_UNREACH_NET_UNKNOWN
                            s = verbose ? "Unknown network" : "!U";
                            break;

                        case 7:	  // ICMP_UNREACH_HOST_UNKNOWN
                            s = verbose ? "Unknown host" : "!W";
                            break;

                        case 8:	  // ICMP_UNREACH_ISOLATED
                            s = verbose ? "Source route isolated" : "!I";
                            break;

                        case 9:	  // ICMP_UNREACH_NET_PROHIB
                            s = verbose ? "Admin prohibited network" : "!A";
                            break;

                        case 10:  // ICMP_UNREACH_HOST_PROHIB
                            s = verbose ? "Admin prohibited host" : "!Z";
                            break;

                        case 11:  // ICMP_UNREACH_TOSNET
                            s = verbose ? "Bad tos for network" : "!Q";
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
			
                
                if (ip->ip_src.s_addr == dst.s_addr) {
                    if (code == -1) { // seems impossible but really happen
                        s = verbose ? "Time to live exceed" : "!TTL";
                        found = false;
                    }
                    else
                        found = true;
                }

                if (!s.empty()) s.insert(0, "  ");
                if (!msg.empty()) msg += " ";

                std::printf("%s  %s%.3f ms", s.c_str(),
                            (verbose > 2) ? msg.c_str() : "", rtt);
            }
            std::cout << std::endl;

	    
            if (found || unreachable) {
		if (!reverse)
		    break;
	    }
        }

	if (found || unreachable) {
	    for (probe = probeVec.begin();
		 probe != probeVec.end() && (*probe)->getProtocol() != IPPROTO_TCP;
		 ++probe)
		;
                
	    if (probe != probeVec.end() && savecode) {
		TcpProbeSock *tcpProbe = dynamic_cast<TcpProbeSock *>(*probe);
		if (!tcpProbe)
		    throw std::bad_cast();
		assert(dport == tcpProbe->getTcpDstPort());
		    
		dport = tcpProbe->getTcpDstPort();
		    
		if (connfd >= 0) {
		    if (verbose > 3)
			std::cerr << "closing connfd " << connfd << std::endl;

		    if (simulate) {

			// Send the previously sent cheat bytes through the
			// normal write() to prevent both sides from
			// continuing to send ack to each other so that they
			// can't close.
			    
			bzero(buf, sizeof(buf));
			int val = tcpProbe->getPmtu() -
				  tcpProbe->getIphdrLen() -
				  tcpProbe->getProtocolHdrLen();  
			
			if (write(connfd, buf, val) != val)
			    throw ProbeException("write");
		    }

		    close(connfd);
		    std::cout << "Port " << dport << " open" << std::endl;
		}
		    
		else if (conn)
		    std::cout << "Port " << dport << " closed" << std::endl;
		else {
		    switch (savecode) {
		    case 1:
			if (tcpFlags == TH_SYN)
			    std::cout << "Port " << dport << " closed" << std::endl;
			else
			    std::cout << "Port " << dport << " closed/filtered" << std::endl;
			break;

		    case 2:
			std::cout << "Port " << dport << " open" << std::endl;
			break;

		    default:
			// Target host may sent the ICMP or UDP packet, so
			// can't get the TCP state.
			std::cout << "Port " << dport << " state unknown" << std::endl;
		    }
		}
	    }
	}

        for (probe = probeVec.begin(); probe != probeVec.end(); ++probe)
            delete *probe;
	
#ifdef _CYGWIN
        if (Sendfp)
            pcap_close(Sendfp);
#endif
	
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
    // std::cerr << "connfd = " << connfd << " origttl = " << origttl << std::endl;
    if (connfd >= 0 && origttl > 0) {
        // Resume the original TTL to ensure that we can discard the
        // connection successfully.
	// Fix me: An error of EINVAL will occur if the write() packets does not
        // reach the destination.
        if (setsockopt(connfd, IPPROTO_IP, IP_TTL, &origttl, sizeof(origttl) < 0))
	    ;
	    // std::perror("setsockopt connfd");

        if (close(connfd) < 0)
	    ;
	    // std::perror("close connfd");
    }
}
	
