#include "ProbeRoute.hpp"
#include <assert.h>

void ProbeAddressInfo::getDeviceInfo() throw(ProbeException)
{
    int sockfd;
    int lastlen, len;
    short flags, mtu;
    struct ifconf ifc;
    struct ifreq *ifr, ifrcopy;
    struct sockaddr_in *sinptr;
    struct sockaddr *addr, *brdaddr, *netmask;
    char *buf, *ptr;
    char *cptr;
    std::string name;

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

    for (ptr = buf; ptr < buf + ifc.ifc_len; ) {
	ifr = (struct ifreq *)ptr;

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

	// deviceInfoPtr->flags = flags;	     // IFF_xxx values

#if defined(SIOCGIFMTU) && defined(HAVE_STRUCT_IFREQ_IFR_MTU)
	if (ioctl(sockfd, SIOCGIFMTU, &ifrcopy) < 0)
	    throw ProbeException("ioctl SIOCGIFMTU");
	mtu = ifrcopy.ifr_mtu;
#else
	mtu = 0;
#endif

        name = ifr->ifr_name;
	
	assert(ifr->ifr_addr.sa_family == AF_INET);

	sinptr = (struct sockaddr_in *)&ifr->ifr_addr;
	addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
        // std::printf("addr: %p\n", addr);
	if (!addr)
	    throw ProbeException("calloc");
	memcpy(addr, sinptr, sizeof(struct sockaddr_in));

#ifdef SIOCGIFBRDADDR
	if (flags & IFF_BROADCAST) {
	    if (ioctl(sockfd, SIOCGIFBRDADDR, &ifrcopy) < 0)
		throw ProbeException("ioctl SIOCGIFBRDADDR");
	    sinptr = (struct sockaddr_in *)&ifrcopy.ifr_broadaddr;
	    brdaddr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
	    if (!brdaddr)
		throw ProbeException("calloc");
	    memcpy(brdaddr, sinptr, sizeof(struct sockaddr_in));
	}
#else
	brdaddr = (struct sockaddr *)NULL;
#endif

#ifdef SIOCGIFNETMASK
	if (ioctl(sockfd, SIOCGIFNETMASK, &ifrcopy) < 0)
	    throw ProbeException("ioctl SIOCGIFNETMASK");
	sinptr = (struct sockaddr_in *)&ifrcopy.ifr_addr;
	netmask = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
	if (!netmask)
	    throw ProbeException("calloc");
	memcpy(netmask, sinptr, sizeof(struct sockaddr_in));
#else
	netmask = (struct sockaddr *)NULL;
#endif

	// insert the device information to the list
	deviceInfoList.push_back(deviceInfo(name,
                                            mtu,
                                            flags,
                                            addr,
                                            brdaddr,
                                            netmask));
    }
    
}

void ProbeAddressInfo::printDeviceInfo()
{
    struct sockaddr_in *sinptr;

    for (std::list<deviceInfo>::iterator it = deviceInfoList.begin();
	 it != deviceInfoList.end(); ++it) {
	std::cout << it->name << ": ";

	sinptr = (struct sockaddr_in *)it->addr;
	std::cout << "inet " << inet_ntoa(sinptr->sin_addr) << ' ';

	if (it->netmask) {
	    sinptr = (struct sockaddr_in *)it->netmask;
	    std::cout << "netmask " << inet_ntoa(sinptr->sin_addr) << ' ';
	}

	if (it->brdaddr) {
	    sinptr = (struct sockaddr_in *)it->brdaddr;
	    std::cout << "broadcast " << inet_ntoa(sinptr->sin_addr) << ' ';
	}

	std::cout << "mtu " << it->mtu << std::endl;
    }

}

void ProbeAddressInfo::clearDeviceInfo()
{
    for (std::list<deviceInfo>::iterator it = deviceInfoList.begin();
	 it != deviceInfoList.end(); ++it) {
	safeFree(it->addr); safeFree(it->brdaddr); safeFree(it->netmask);
    }

    deviceInfoList.clear();
}

ProbeAddressInfo::ProbeAddressInfo(const char *foreignHost, const char *foreignService,
                                   const char *localHost, int localPort,
                                   const char *dev, int mtu) throw(ProbeException)
    // : device(dev), devMtu(mtu)
{
    struct addrinfo hints, *res, *curr;
    struct sockaddr_in *paddr;
    int n;

    bzero(&hints, sizeof(struct addrinfo));

    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;

    if ((n = getaddrinfo(foreignHost, foreignService, &hints, &res)) != 0)
        throw ProbeException("getaddrinfo error", gai_strerror(n));

    bzero(&localAddr, sizeof(struct sockaddr));

    sockfd = -1;
    // assert(res);

    for (curr = res; curr && sockfd < 0; curr = curr->ai_next)
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
	    if (connect(sockfd, curr->ai_addr, curr->ai_addrlen) < 0) {
		close(sockfd);
		sockfd = -1;
	    }
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

    // anyway, we define the local port ourselves
    paddr->sin_port = htons(localPort);

#if 0
    // fetch the device name or mtu size by the IP address
    getDeviceInfo();
    int exist = 0;
    for (std::list<deviceInfo>::iterator it = deviceInfoList.begin();
	 it != deviceInfoList.end(); ++it) {
	if (dev && device == it->name) exist = 1;

	if (((struct sockaddr_in *)it->addr)->sin_addr.s_addr ==
	    ((struct sockaddr_in *)&localAddr)->sin_addr.s_addr) {
	    if (!dev) device = it->name;
	    if (!mtu) devMtu = it->mtu;
	}
    }
    clearDeviceInfo();
    if (!exist)
	throw ProbeException("device not exist");
#endif

}

