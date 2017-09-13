#include "ProbeRoute.hpp"

int main(int argc, char *argv[])
{
    try {
	if (argc != 3)
	    throw ProbeException("Usage: proberoute <host> <service>");

	ProbeAddressInfo addressInfo(argv[1], argv[2]);
    
	std::cout << addressInfo << std::endl;
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
    
