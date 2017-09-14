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

	mtu = addressInfo.getDevMtu();
	sinptr = (struct sockaddr_in *)addressInfo.getLocalSockaddr();
	src = sinptr->sin_addr;
	sinptr = (struct sockaddr_in *)addressInfo.getForeignSockaddr();
	dst = sinptr->sin_addr;
	
	TcpProbeSock probeSock(mtu, 0, src, dst, 4);

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
    
