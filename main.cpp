#include "ProbeRoute.hpp"

int main(int argc, char *argv[])
{
    try {
	if (argc != 3)
	    throw ProbeException("Usage: proberoute <host> <service>");

	ProbeAddressInfo addressInfo(argv[1], argv[2]);
    
	std::cout << addressInfo << std::endl;

	u_char buf[MAX_MTU];
	memset(buf, 0xa5, sizeof(buf)); // just pad pattern

	int mtu;
	struct in_addr src, dst;
	struct sockaddr_in *sinptr;
	int len, iplen, tcplen;
	u_short sport, dport;

	mtu = addressInfo.getDevMtu();

	sinptr = (struct sockaddr_in *)addressInfo.getLocalSockaddr();
	src = sinptr->sin_addr;
	sport = ntohs(sinptr->sin_port);

	sinptr = (struct sockaddr_in *)addressInfo.getForeignSockaddr();
	dst = sinptr->sin_addr;
	dport = ntohs(sinptr->sin_port);
	
	TcpProbeSock probeSock(mtu, 0, src, dst, 0, NULL, 4);
	iplen = probeSock.getIphdrLen();
	tcplen = probeSock.getTcphdrLen();

	std::cout << "iplen = " << iplen
		  << " tcplen = " << tcplen << std::endl;

	len = probeSock.buildProtocolPacket(buf, mtu - iplen, 255, IP_DF,
					    sport, dport, 0, 0); 

	std::cout << "total len = " << len << std::endl;

	std::cout << probeSock << std::endl;

	probeSock.sendPacket(buf, len, 0, addressInfo.getForeignSockaddr(), addressInfo.getForeignSockaddrLen());
	// probeSock.buildProtocolPacket(buf, mtu,

        // addressInfo.getDeviceInfo();
        // addressInfo.printDeviceInfo();
        // addressInfo.freeDeviceInfo();
        // std::cout << "clear\n";
        // addressInfo.printDeviceInfo();

    } catch (ProbeException &e) {
	std::cerr << e.what() << std::endl;
	exit(1);
    }
    return 0;
}
    
