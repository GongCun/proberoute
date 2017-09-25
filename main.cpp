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
int echo, timestamp;
const char *host, *service, *srcip;
u_char flags = TH_SYN;

#define printOpt(x) std::cout << #x": " << x << std::endl

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
    printOpt(echo);
    printOpt(timestamp);
    printOpt(nullToEmpty(host));
    printOpt(nullToEmpty(service));
    printOpt(nullToEmpty(srcip));
    std::printf("flags: 0x%02x\n", flags);
}

int main(int argc, char *argv[])
{
    const int on = 1;
    int connfd = -1;
    std::string msg;
    struct linger linger;
    int n;
    socklen_t optlen;
    int origttl = 0, ttl;
    const u_char *ptr;
    struct sockaddr_in *sinptr;
    struct in_addr src, dst, lastrecv;
    int caplen, len, iplen, packlen;
    u_short sport, dport;


    // make cout unbuffered
    std::cout.setf(std::ios::unitbuf);

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

        ProbePcap capture(addressInfo.getDevice().c_str(),
                          "tcp or icmp[0:1] == 3 or icmp[0:1] == 11 or icmp[0:1] == 12");

	switch (protocol) {
	case IPPROTO_TCP:
	    if (conn && !addressInfo.isSameLan()) { // no need use connect probe
		if ((connfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		    throw ProbeException("socket");

		linger.l_onoff = 1, linger.l_linger = 0;
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

                    optlen = sizeof(origttl);
                    if (getsockopt(connfd, IPPROTO_IP, IP_TTL, &origttl, &optlen) < 0)
                        throw ProbeException("getsockopt IP_TTL");

                    ttl = 1;
                    if (setsockopt(connfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
                        throw ProbeException("setsockopt IP_TTL");

                    if (write(connfd, "\xa5", 1) != 1)
                        throw ProbeException("write");
                        
                    // capture the write() packet immediately or when it retransmit
                    uint16_t ipid = 0;
                    uint32_t seq = 0, ack = 0;
                    sinptr = (struct sockaddr_in *)addressInfo.getLocalSockaddr();
                    src = sinptr->sin_addr;
                    sport = ntohs(sinptr->sin_port);

                    sinptr = (struct sockaddr_in *)addressInfo.getForeignSockaddr();
                    dst = sinptr->sin_addr;
                    dport = ntohs(sinptr->sin_port);
	
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
                                ack
                            ))
                            break;
                    }
                    if (verbose > 2)
                        std::cerr << "captured ipid " << ipid
                                  << " seq " << seq
                                  << " ack " << ack << std::endl;

		    // set out-of-order sequence
		    ++ipid, ++seq;
                    
		}
		else if (n > 0) {
		    // connection refused or timed out
		    if (verbose)
			std::cerr << "can't connect to " << host
                                  << " (" << service <<")"
                                  << std::endl;
		}
		else {
                    close(connfd);
		    throw ProbeException("nonbConn");
                }
                		
	    }
	    break;                // IPPROTO_TCP
	default:
	    std::cerr << "unknown protocol: " << protocol << std::endl;
	    exit(1);
	} // case PROTOCOL
    } catch (ProbeException &e) {
	std::cerr << e.what() << std::endl;
	exit(1);
    }


    return 0;

#if 0
    try {
	if (argc != 3)
	    throw ProbeException("Usage: proberoute <host> <service>");


	u_char buf[MAX_MTU];
	memset(buf, 0xa5, sizeof(buf)); // just pad pattern

	int mtu;
	struct in_addr src, dst, lastrecv;
	struct sockaddr_in *sinptr;
	int len, iplen, packlen;
	u_short sport, dport;

	mtu = addressInfo.getDevMtu();

	sinptr = (struct sockaddr_in *)addressInfo.getLocalSockaddr();
	src = sinptr->sin_addr;
	sport = ntohs(sinptr->sin_port);

	sinptr = (struct sockaddr_in *)addressInfo.getForeignSockaddr();
	dst = sinptr->sin_addr;
	dport = ntohs(sinptr->sin_port);
	
	TcpProbeSock probeSock(mtu, src, dst, 0, NULL, 4);
	std::cout << probeSock << std::endl;

	iplen = probeSock.getIphdrLen();
	packlen = probeSock.getTcphdrLen();
	std::cerr << "packlen = " << packlen << std::endl;
	probeSock.buildProtocolHeader(buf, packlen, sport, dport);

        int ttl, nprobe, i, maxttl = 30, fragsize = 0;
        int waittime = 1;
        int caplen;
        const u_char *ptr;
        const struct ip *ip;
        bool found = false;
        struct timeval tv;
        double rtt;

        nprobe = 3;

        // make cout unbuffered
        std::cout.setf(std::ios::unitbuf);

        ProbePcap capture(addressInfo.getDevice().c_str(),
                          "tcp or icmp[0:1] == 3 or icmp[0:1] == 11 or icmp[0:1] == 12");

#if 0
	if (signal(SIGALRM, sig_alrm) == SIG_ERR)
            throw ProbeException("signal error");
#endif

        for (ttl = 1; ttl < maxttl; ++ttl) {
            std::printf("%3d ", ttl);
            for (i = 0; i < nprobe; i++) {
                if (gettimeofday(&tv, NULL) < 0)
                    throw ProbeException("gettimeofday");

                if (fragsize)
                    probeSock.sendFragPacket(buf, packlen, ttl, fragsize,
                                             addressInfo.getForeignSockaddr(),
                                             addressInfo.getForeignSockaddrLen());
                else {
                    
                    len = probeSock.buildProtocolPacket(buf, packlen, ttl,
                                                        IP_DF, sport, dport);
                    probeSock.sendPacket(buf, len, 0,
                                         addressInfo.getForeignSockaddr(),
                                         addressInfo.getForeignSockaddrLen());
                }
                
                alarm(waittime);

                if (sigsetjmp(jumpbuf, 1) != 0) {
                    std::cout << " *";
                    alarm(0);
                    continue;
                }

                for ( ; ; ) {
                    ptr = capture.nextPcap(&caplen);
                    assert(ptr != NULL);
                    if (probeSock.recvIcmp(ptr, caplen) ||
                        probeSock.recvTcp(ptr, caplen, sport, dport) > 0)
                        break;
                }

                if ((rtt = delta(&tv)) < 0)
                    throw ProbeException("delta");
                ip = (struct ip *)ptr;
                if (memcmp(&ip->ip_src, &lastrecv, sizeof(struct in_addr)) ||
                    i == 0) {
                    std::cout << " " << inet_ntoa(ip->ip_src);
                    lastrecv = ip->ip_src;
                }
                std::printf(" %.3f ms", rtt);
                
                if (ip->ip_src.s_addr == dst.s_addr)
                    found = true;
            }
            std::cout << std::endl;
            if (found) break;
        }



	// std::cout << "total len = " << len << std::endl;



        // std::cout << "clear\n";
        // addressInfo.printDeviceInfo();

    } catch (ProbeException &e) {
	std::cerr << e.what() << std::endl;
	exit(1);
    }
#endif

}
    
