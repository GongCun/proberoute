#include "ProbeRoute.hpp"
#include <assert.h>
// #include <getopt.h>

sigjmp_buf jumpbuf;
int verbose;
int protocol;
int sport;
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
u_char flags;

static void usage()
{
#define P(s) std::cerr << s << std::endl
#include "usage.h"
#undef P
    exit(1);
}

#define printOpt(x) std::cout << #x": " << x << std::endl

static void printOpts()
{
    printOpt(verbose);
    printOpt(protocol);
    printOpt(sport);
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
    if (parseOpt(argc, argv) < 0)
        usage();

    printOpts();

    return 0;

#if 0
    try {
	if (argc != 3)
	    throw ProbeException("Usage: proberoute <host> <service>");

	ProbeAddressInfo addressInfo(argv[1], argv[2]);
    
	std::cout << addressInfo << std::endl;

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



        // addressInfo.getDeviceInfo();
        // addressInfo.printDeviceInfo();
        // addressInfo.freeDeviceInfo();
        // std::cout << "clear\n";
        // addressInfo.printDeviceInfo();

    } catch (ProbeException &e) {
	std::cerr << e.what() << std::endl;
	exit(1);
    }
#endif

}
    
