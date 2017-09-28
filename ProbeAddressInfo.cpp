#include "ProbeRoute.hpp"
#include <assert.h>
#include <errno.h>

void ProbeAddressInfo::getDeviceInfo() throw(ProbeException)
{
    int sockfd;
    int lastlen, len, flags;
    struct ifconf ifc;
    struct ifreq *ifr, ifrcopy;
    struct sockaddr_in *sinptr;
    char *buf, *ptr;
    char *cptr;
    struct deviceInfo *deviceInfoPtr, **deviceInfoNext;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        throw ProbeException("socket error");

    lastlen = 0;
    len = 100 * sizeof(struct ifreq);        // initial buffer size guess

    // If the buffer length is not large enough, the result is
    // truncated and ioctl() return success. So we need issue the
    // request again with a large buffer, and compare the length with
    // the saved value. Only if the two lengths are the same is our
    // buffer large enough.
    for ( ; ; ) {
        if ((buf = (char *)malloc(len)) == NULL)
            throw ProbeException("malloc error");
        ifc.ifc_len = len;
        ifc.ifc_buf = buf;

        if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
            if (errno != EINVAL || lastlen != 0)
                throw ProbeException("ioctl SIOCGIFCONF");
        } else {
            if (ifc.ifc_len == lastlen)
                break;                       // success, len has not changed
            lastlen = ifc.ifc_len;
        }

        len += 10 * sizeof(struct ifreq);    // increment
        free(buf);
    }

    deviceInfoList = NULL;
    deviceInfoNext = &deviceInfoList;

    for (ptr = buf; ptr < buf + ifc.ifc_len; ) {
	ifr = (struct ifreq *)ptr;

#ifdef _LINUX
	ptr += sizeof(*ifr);
#else
#ifdef HAVE_SOCKADDR_SA_LEN
	len = std::max(static_cast<int>(sizeof(struct sockaddr)),
		       static_cast<int>(ifr->ifr_addr.sa_len));
#else
	switch (ifr->ifr_addr.sa_family) {
#ifdef IPV6
	case AF_INET6:
	    len = sizeof(struct sockaddr_in6);
	    break;
#endif
	case AF_INET:
	default:
	    len = sizeof(struct sockaddr);
	    break;
	}
#endif	// HAVE_SOCKADDR_SA_LEN
	ptr += sizeof(ifr->ifr_name) + len;  // for next one in buffer
#endif  // _LINUX 

	if (ifr->ifr_addr.sa_family != AF_INET)
	    continue;

	if ((cptr = strchr(ifr->ifr_name, ':')) != NULL)
	    *cptr = 0;			     // replace colon with null, but we don't
					     // check if alias.
	ifrcopy = *ifr;
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifrcopy) < 0)
	    throw ProbeException("ioctl SIOCGIFFLAGS");
	if (((flags = ifrcopy.ifr_flags) & IFF_UP) == 0)
	    continue;			     // ignore if interface not up

        deviceInfoPtr = new deviceInfo;
        *deviceInfoNext = deviceInfoPtr;       // prev points to this new one
        deviceInfoNext = &deviceInfoPtr->next; // points to next one goes here
        
	deviceInfoPtr->flags = flags;          // IFF_xxx values

#if defined(SIOCGIFMTU) && defined(HAVE_STRUCT_IFREQ_IFR_MTU)
	if (ioctl(sockfd, SIOCGIFMTU, &ifrcopy) < 0)
	    throw ProbeException("ioctl SIOCGIFMTU");
	deviceInfoPtr->mtu = ifrcopy.ifr_mtu;
#endif

        deviceInfoPtr->name = ifr->ifr_name;
	
	assert(ifr->ifr_addr.sa_family == AF_INET);

	sinptr = (struct sockaddr_in *)&ifr->ifr_addr;
	deviceInfoPtr->addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
	if (!deviceInfoPtr->addr) throw ProbeException("calloc");
	memcpy(deviceInfoPtr->addr, sinptr, sizeof(struct sockaddr_in));

#ifdef SIOCGIFBRDADDR
	if (flags & IFF_BROADCAST) {
	    if (ioctl(sockfd, SIOCGIFBRDADDR, &ifrcopy) < 0)
		throw ProbeException("ioctl SIOCGIFBRDADDR");
	    sinptr = (struct sockaddr_in *)&ifrcopy.ifr_broadaddr;
	    deviceInfoPtr->brdaddr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
	    if (!deviceInfoPtr->brdaddr) throw ProbeException("calloc");
	    memcpy(deviceInfoPtr->brdaddr, sinptr, sizeof(struct sockaddr_in));
	}
#endif

#ifdef SIOCGIFNETMASK
	if (ioctl(sockfd, SIOCGIFNETMASK, &ifrcopy) < 0)
	    throw ProbeException("ioctl SIOCGIFNETMASK");
	sinptr = (struct sockaddr_in *)&ifrcopy.ifr_addr;
	deviceInfoPtr->netmask = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
	if (!deviceInfoPtr->netmask) throw ProbeException("calloc");
	memcpy(deviceInfoPtr->netmask, sinptr, sizeof(struct sockaddr_in));
#endif

    }
    close(sockfd);
    free(buf);
}

void ProbeAddressInfo::deviceInfo::print()
{
    struct sockaddr_in *sinptr;

    std::cout << name << ": ";

    sinptr = (struct sockaddr_in *)addr;
    std::cout << "inet " << inet_ntoa(sinptr->sin_addr) << ' ';

    if (netmask) {
        sinptr = (struct sockaddr_in *)netmask;
        std::cout << "netmask " << inet_ntoa(sinptr->sin_addr) << ' ';
    }

    if (brdaddr) {
        sinptr = (struct sockaddr_in *)brdaddr;
        std::cout << "broadcast " << inet_ntoa(sinptr->sin_addr) << ' ';
    }

    std::cout << "mtu " << mtu << std::endl;
}

    
void ProbeAddressInfo::printDeviceInfo()
{
    struct deviceInfo *deviceInfoPtr;

    for (deviceInfoPtr = deviceInfoList; deviceInfoPtr;
         deviceInfoPtr = deviceInfoPtr->next) {
        deviceInfoPtr->print();
    }

}

void ProbeAddressInfo::freeDeviceInfo()
{
    struct deviceInfo *p, *pnext;
    // struct sockaddr_in *ptr;

    for (p = deviceInfoList; p; p = pnext) {
        pnext = p->next;	// can't fetch pnext after delete
        delete p;		// the p{} itself
    }

    deviceInfoList = NULL;	// avoid double printDeviceInfo()
}

ProbeAddressInfo::ProbeAddressInfo(const char *foreignHost, const char *foreignService,
                                   const char *localHost, int localPort,
                                   const char *dev, u_short mtu) throw(ProbeException)
    : device(nullToEmpty(dev)), devMtu(mtu), sameLan(true)
{
    struct addrinfo hints, *res, *curr;
    struct sockaddr_in *paddr;
    int sockfd;
    int n;
    bool exist = false;

    bzero(&hints, sizeof(struct addrinfo));

    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;

    if (foreignService == NULL)
	foreignService = "33434"; // default is 32768 + 666 = 33434

    if ((n = getaddrinfo(foreignHost, foreignService, &hints, &res)) != 0)
        throw ProbeException("getaddrinfo error", gai_strerror(n));

    bzero(&localAddr, sizeof(struct sockaddr));

    sockfd = -1;

    for (curr = res; curr && sockfd < 0; curr = curr->ai_next)
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
	    if (connect(sockfd, curr->ai_addr, curr->ai_addrlen) < 0) {
		close(sockfd);
		sockfd = -1;
	    } else
		break;
	}

    if (sockfd < 0) {
	freeaddrinfo(res);
	throw ProbeException("Unable to connect by UDP");
    }

    foreignAddrLen = curr->ai_addrlen;
    memcpy(&foreignAddr, curr->ai_addr, foreignAddrLen);
    freeaddrinfo(res);

    paddr = (struct sockaddr_in *)&localAddr;
    localAddrLen = sizeof(struct sockaddr_in);

    if (localHost == NULL) {
        if (getsockname(sockfd, &localAddr, &localAddrLen) < 0)
            throw ProbeException("getsockname");
    } else {
        if (inet_pton(AF_INET, localHost, &paddr->sin_addr) != 1)
            throw ProbeException("inet_pton error");
    }

    // specify the local port
    if (localPort)
	paddr->sin_port = htons(localPort);

    close(sockfd);

    // fetch the device name or mtu size by the IP address
    getDeviceInfo();
    
    struct deviceInfo *p;
    for (p = deviceInfoList; p; p = p->next) {
	if (((struct sockaddr_in *)p->addr)->sin_addr.s_addr ==
	    ((struct sockaddr_in *)&localAddr)->sin_addr.s_addr) {
	    if (device.empty()) {
                device = p->name;
            }
	    if (!devMtu) devMtu = p->mtu;
	}

	if (!device.empty() && device == p->name) {
	    exist = true;
	    if (!devMtu) devMtu = p->mtu;
            break;
        }
    }

    if (!exist) {
        freeDeviceInfo();
	throw ProbeException("device not exist");
    }

    if (verbose > 2) p->print();  // the iface address maybe different from
                                  // specified source address

    // Determine whether the remote host and local host are in the
    // same LAN
    const uint32_t vlan = *((uint32_t *)&((struct sockaddr_in *)p->addr)->sin_addr) &
                          *((uint32_t *)&((struct sockaddr_in *)p->netmask)->sin_addr);
    
    char strdst[INET_ADDRSTRLEN], strbrd[INET_ADDRSTRLEN], strvlan[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, (struct in_addr *)&vlan, strvlan, sizeof(strvlan));

    inet_ntop(AF_INET, &((struct sockaddr_in *)p->brdaddr)->sin_addr,
              strbrd, sizeof(strbrd));

    inet_ntop(AF_INET, &((struct sockaddr_in *)&foreignAddr)->sin_addr,
              strdst, sizeof(strdst));
    
    if (verbose > 2)
        std::cerr << "strlan: " << strvlan << " "
                  << "strbrd: " << strbrd << " "
                  << "strdst: " << strdst << std::endl;

    if (!(strcmp(strdst, strvlan) >= 0 &&
          strcmp(strdst, strbrd) <= 0))
        sameLan = false;
    
    freeDeviceInfo();
}

