#include "ProbeRoute.hpp"
#include <assert.h>
#include <errno.h>

// static data member must be defined (exactly once) outside the class body
struct ProbeAddressInfo::deviceInfo *
ProbeAddressInfo::deviceInfoList = NULL;

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

#if defined _LINUX || defined _CYGWIN
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

#ifdef _CYGWIN
        deviceInfoPtr->name.insert(0, PCAP_SRC_IF_STRING "\\Device\\NPF_");
#endif

        // std::cerr << "ifr->ifr_name = " << ifr->ifr_name << std::endl;
        // std::cerr << "deviceInfoPtr->name = " << deviceInfoPtr->name << std::endl;

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

#ifdef SIOCGIFDSTADDR
	if (flags & IFF_POINTOPOINT) {
	    if (ioctl(sockfd, SIOCGIFDSTADDR, &ifrcopy) < 0)
		throw ProbeException("ioctl SIOCGIFDSTADDR");
	    sinptr = (struct sockaddr_in *)&ifrcopy.ifr_dstaddr;
	    deviceInfoPtr->dstaddr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
	    if (!deviceInfoPtr->dstaddr) throw ProbeException("calloc");
	    memcpy(deviceInfoPtr->dstaddr, sinptr, sizeof(struct sockaddr_in));
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

    if (addr) {
	sinptr = (struct sockaddr_in *)addr;
	std::cout << "inet " << inet_ntoa(sinptr->sin_addr) << ' ';
    }

    if (netmask) {
        sinptr = (struct sockaddr_in *)netmask;
        std::cout << "netmask " << inet_ntoa(sinptr->sin_addr) << ' ';
    }

    if (brdaddr) {
        sinptr = (struct sockaddr_in *)brdaddr;
        std::cout << "broadcast " << inet_ntoa(sinptr->sin_addr) << ' ';
    }

    if (dstaddr) {
	sinptr = (struct sockaddr_in *)dstaddr;
	std::cout << "dstaddr " << inet_ntoa(sinptr->sin_addr) << ' ';
    }

    std::cout << "mtu " << mtu << std::endl;
}

void ProbeAddressInfo::deviceInfo::list()
{
    struct sockaddr_in *sinptr;

    sinptr = (struct sockaddr_in *)addr;

    std::cout << name << ' ' << inet_ntoa(sinptr->sin_addr) << std::endl;

    return;
}

void ProbeAddressInfo::printDeviceInfo()
{
    struct deviceInfo *deviceInfoPtr;

    for (deviceInfoPtr = deviceInfoList; deviceInfoPtr;
         deviceInfoPtr = deviceInfoPtr->next) {
        deviceInfoPtr->print();
    }

}

void ProbeAddressInfo::listDeviceInfo()
{
    int i;
    struct deviceInfo *deviceInfoPtr;

    for (i = 1, deviceInfoPtr = deviceInfoList;
	 deviceInfoPtr;
         deviceInfoPtr = deviceInfoPtr->next, ++i) {
	std::cout << i << ". ";
        deviceInfoPtr->list();
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

    bzero(&localAddr, sizeof(struct sockaddr));
    bzero(&foreignAddr, sizeof(struct sockaddr));

    if ((n = getaddrinfo(foreignHost, foreignService, &hints, &res)) != 0)
        throw ProbeException("getaddrinfo error", gai_strerror(n));



    sockfd = -1;

    for (curr = res; curr && sockfd < 0; curr = curr->ai_next)
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
            // Get destination, gateway and netmask. To get the destination
            // network and netmask, must writing and reading the routing socket
            // before call connect().
            bzero(strDestination, sizeof(strDestination));
            bzero(strGateway, sizeof(strGateway));
            bzero(strDestinationMask, sizeof(strDestinationMask));
            paddr = (struct sockaddr_in *)curr->ai_addr;
            getRouteInfo(&paddr->sin_addr);

            // Get the outgoing interface.
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

        if (getsockname(sockfd, &localAddr, &localAddrLen) < 0)
            throw ProbeException("getsockname");
    if (localHost)              // use the given IP instead of detected IP
        if (inet_pton(AF_INET, localHost, &paddr->sin_addr) != 1)
            throw ProbeException("inet_pton error");

    // specify the local port
    if (localPort)
	paddr->sin_port = htons(localPort);

    close(sockfd);

    // fetch the device name or mtu size by the IP address
    getDeviceInfo();

    // std::cerr << "localAddr = " << inet_ntoa(((struct sockaddr_in *)&localAddr)->sin_addr) << std::endl;

    struct deviceInfo *p;
    for (p = deviceInfoList; p; p = p->next) {
        // std::cerr << "p->name = " << p->name << std::endl;
	// std::cerr << "p->addr = " <<
	// inet_ntoa(
            // ((struct sockaddr_in *)p->addr)->sin_addr
        // ) << std::endl;

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

    if (p->netmask && Netmask == NULL) {
	if ((Netmask = (struct sockaddr *)calloc(1, sizeof(struct sockaddr))) == NULL)
	    throw ProbeException("calloc Netmask");
	
	memcpy(Netmask, p->netmask, sizeof(struct sockaddr));
    }
    

    // Compare the destination address with netmask and broadcast
    // address to determine whether the remote host and local host are
    // in the same subnet. _CAN'T_ use this method since the
    // point-to-point protocol have _NO_ broadcast address.
    if (p->addr && p->brdaddr && p->netmask) {
	
	const uint32_t vlan = *((uint32_t *)&((struct sockaddr_in *)p->addr)->sin_addr) &
			      *((uint32_t *)&((struct sockaddr_in *)p->netmask)->sin_addr);

	char strdst[INET_ADDRSTRLEN], strbrd[INET_ADDRSTRLEN], strvlan[INET_ADDRSTRLEN];

	if (!inet_ntop(AF_INET, (struct in_addr *)&vlan,
		       strvlan, sizeof(strvlan)))
	    throw ProbeException("inet_ntop vlan");

	if (!inet_ntop(AF_INET, &((struct sockaddr_in *)p->brdaddr)->sin_addr,
		       strbrd, sizeof(strbrd)))
	    throw ProbeException("inet_ntop brdaddr");

	if (!inet_ntop(AF_INET, &((struct sockaddr_in *)&foreignAddr)->sin_addr,
		       strdst, sizeof(strdst)))
	    throw ProbeException("inet_ntop foreignAddr");

	if (verbose > 2)
	    std::cerr << "strlan: " << strvlan << " "
		      << "strbrd: " << strbrd << " "
		      << "strdst: " << strdst << std::endl;

	if (!(strcmp(strdst, strvlan) >= 0 &&
	      strcmp(strdst, strbrd) <= 0))
	    sameLan = false;
    }

    // Check the gateway again strictly
    if (!strcmp(strGateway, "AF_LINK"))
        sameLan = true;

    // Check the Point-to-Point destination address again (Type AF_LINK)
    if (p->addr && p->dstaddr && p->netmask) {
	const uint32_t svlan = *((uint32_t *)&((struct sockaddr_in *)p->addr)->sin_addr) &
			       *((uint32_t *)&((struct sockaddr_in *)p->netmask)->sin_addr);
	const uint32_t dvlan = *((uint32_t *)&((struct sockaddr_in *)&foreignAddr)->sin_addr) &
			       *((uint32_t *)&((struct sockaddr_in *)p->netmask)->sin_addr);

	sameLan = (svlan == dvlan) ? true : false;
    }

    freeDeviceInfo();
}

/*
 * From UNP Chapter 18 "Routing Sockets", Section 18.3 "Reading and Writing"
 *

   buffer sent to kernel        buffer returned from kernel
   +--------------+             +--------------+
   | rt_msghdr{}  |             | rt_msghdr{}  |
   |  RTM_GET     |             |  RTM_GET     |
   +--------------+             +--------------+
   | destination  | RTA_DST     | destination  | RAT_DST
   | sockaddr{}   |             | sockaddr{}   |
   +--------------+             +--------------+
                                | gateway      | RTA_GATEWAY
                                | sockaddr{}   |
                                +--------------+
                                | netmask      | RTA_NETMASK
                                | sockaddr{}   |
                                +--------------+
                                | genmask      | RTA_GENMASK
                                | sockaddr{}   |
                                +--------------+

    The socket address structures are variable-length. There are two
    complications that must be handled. First, the two masks, the network mask
    and the cloning mask, can be returned in a socket address structures with an
    sa_len of 0 (assumes that has an sa_len field), but this really occupies the
    size of an unsigned long. This value represents a mask of all zero bits
    (0.0.0.0). Second, each socket address structure can be padded at the end so
    that the next one begins on a specific boundary, which is the size of an
    unsigned long (e.g., a 4-byte boundary for a 32-bit architecture). Although
    sockaddr_in structures occupy 16 bytes, which requires no padding, the masks
    often have padding at the end.
 */

static struct sockaddr *NEXT_SA(const struct sockaddr *sa);
extern "C" {
    static const char *sock_ntop(const struct sockaddr *sa, char *buf, const ssize_t size);
    static const char *mask_ntop(const struct sockaddr *sa, char *buf, const ssize_t size);
}

#if !defined _LINUX && !defined _CYGWIN && defined HAVE_RT_MSGHDR_STRUCT
void ProbeAddressInfo::getRouteInfo(const struct in_addr *addr) throw(ProbeException)
{
    int sockfd;
    struct rt_msghdr *rtm;
    struct sockaddr *sa, *rti_info[RTAX_MAX];
    struct sockaddr_in *sin;
    char *buf;
    pid_t pid;
    ssize_t n;
    // struct rt_msghdr{} + 8 * struct sockaddr{} < struct rt_msghdr{} + 512
    const int BUFLEN = sizeof(struct rt_msghdr) + 512;
    const int SEQ = 9999;

    if ((sockfd = socket(AF_ROUTE, SOCK_RAW, 0)) < 0) {
        throw ProbeException("socket AF_ROUTE error");
    }

    if ((buf = (char *)calloc(BUFLEN, 1)) == NULL) {
        throw ProbeException("calloc");
    }

    rtm = (struct rt_msghdr *)buf;
    rtm->rtm_msglen = sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in);
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_type = RTM_GET;
    rtm->rtm_addrs = RTA_DST;
    rtm->rtm_pid = pid = getpid();
    rtm->rtm_seq = SEQ;

    // std::cerr << "BUFLEN = " << BUFLEN << std::endl;
    // std::cerr << "size of rt_msghdr = " << sizeof(struct rt_msghdr) << std::endl;
    // std::cerr << "rtm_msglen = " << rtm->rtm_msglen << std::endl;

    sin = (struct sockaddr_in *)(rtm + 1);
    sin->sin_len = sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    memcpy(&sin->sin_addr, addr, sizeof(struct in_addr));
    
    if (write(sockfd, rtm, rtm->rtm_msglen) != rtm->rtm_msglen) {
        throw ProbeException("write rtm");
    }
    
    do {
        if ((n = read(sockfd, rtm, BUFLEN)) < 0)
            throw ProbeException("read rtm");
    } while (rtm->rtm_type != RTM_GET ||
             rtm->rtm_seq != SEQ ||
             rtm->rtm_pid != pid);

    close(sockfd);
    // std::cerr << "n = " << n << std::endl;

    rtm = (struct rt_msghdr *)buf;
    sa = (struct sockaddr *)(rtm + 1);

    if (verbose > 2) {
        std::cerr << "routing socket bitmask: ";
        for (int i = 7; i >= 0; i--)
            std::cerr << ((rtm->rtm_addrs >> i) & 1);
        std::cerr << std::endl;
    }
    
    for (int i = 0; i < RTAX_MAX; ++i) {
        if (rtm->rtm_addrs & (1 << i)) { // bitmask identifying sockaddrs in msg
            rti_info[i] = sa;
            sa = NEXT_SA(sa);
        }
        else
            rti_info[i] = NULL;
    }

    if (sa = rti_info[RTAX_DST]) {
        if (sock_ntop(sa, strDestination, sizeof(strDestination)) == NULL)
            throw ProbeException("sock_ntop strDestination");
    }
    if (sa = rti_info[RTAX_GATEWAY]) {
        if (sock_ntop(sa, strGateway, sizeof(strGateway)) == NULL)
            throw ProbeException("sock_ntop strGateway");
    }

    if (sa = rti_info[RTAX_NETMASK]) {
        if (mask_ntop(sa, strDestinationMask, sizeof(strDestinationMask)) == NULL)
            throw ProbeException("mask_ntop strDestinationMask");
    }

    free(buf);
}
#elif defined _LINUX && defined HAVE_RTMSG_STRUCT
// From Stack Overflow: Getting gateway to use for a given ip in ANSI C, asked
// by inquam, answered by nos. Modify according to the Linux manual of
// rtnetlink(7), rtnetlink(3), netlink(7), netlink(3).

extern "C" {
    static int ifname(int ifIndex, char *ifName); 
}

static int ifname(int ifIndex, char *ifName)
{
    static int fd = -1;
    struct ifreq ifr;
    
    if (fd < 0 && (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	return -1;

    ifr.ifr_ifindex = ifIndex;
    if (ioctl(fd, SIOCGIFNAME, &ifr, sizeof(ifr)) < 0)
	return -1;

    strcpy(ifName, ifr.ifr_name);
    return 0;
}


void ProbeAddressInfo::getRouteInfo(const struct in_addr *addr) throw(ProbeException)
{
    struct nlmsghdr *nlMsg;
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    struct RouteInfo 
    {
	struct in_addr dstAddr;
	struct in_addr srcAddr;
	struct in_addr gateWay;
	uint32_t netMask;
	char ifName[IF_NAMESIZE];	// no need, just for debug
    } *rtInfo;

    // struct RouteInfo *rtInfo;
    const int BUFLEN = 8192;
    char msgBuf[BUFLEN];

    int sock;
    const int SEQ = 9999;
    pid_t pid;
    char *ptr;
    int count;
    ssize_t len, msgLen = 0;
   
    if ((sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
	throw ProbeException("socket PF_NETLINK");

    bzero(msgBuf, sizeof(msgBuf));

    nlMsg = (struct nlmsghdr *)msgBuf;
    rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);

    // Fill in the nlmsg header
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE;			   // get the routes from kernel
							   // routing table.
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;	   // request for dump.
    nlMsg->nlmsg_seq = SEQ;				   // sequence of the message
							   // sequence.
    nlMsg->nlmsg_pid = pid = getpid();			   // PID of process sending the
							   // request.
    if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) != nlMsg->nlmsg_len)
	throw ProbeException("send nlmsg");

    ptr = msgBuf;
    do {
	// Receive response from the kernel
	if ((len = recv(sock, ptr, BUFLEN - msgLen, 0)) < 0)
	    throw ProbeException("recv sock");

	nlMsg = (struct nlmsghdr *)ptr;
	// Check if the header is valid
	if (!NLMSG_OK(nlMsg, len))
	    throw ProbeException("received packet");
	if (nlMsg->nlmsg_type == NLMSG_ERROR) {
	    struct nlmsgerr *nlErr = (struct nlmsgerr *)NLMSG_DATA(nlMsg);
	    if (nlErr->error < 0)
		errno = -nlErr->error;
	    throw ProbeException("received packet");
	}

	// Check if it's the last message
	if (nlMsg->nlmsg_type == NLMSG_DONE)
	    break;
	else {
	    // Else move the pointer to buffer appropriately
	    ptr += len;
	    msgLen += len;
	}
	
	// Check if the message is a part of a multipart message terminated by
	// NLMSG_DONE. Return if it's not.
	if ((nlMsg->nlmsg_flags & NLM_F_MULTI) == 0)
	    break;

    } while (nlMsg->nlmsg_seq != (uint32_t)SEQ ||
	     nlMsg->nlmsg_pid != (uint32_t)pid);

    // Parse and record the response
    if ((rtInfo = (struct RouteInfo *)malloc(sizeof(struct RouteInfo))) == NULL)
	throw ProbeException("calloc RouteInfo");

    for (
	nlMsg = (struct nlmsghdr *)msgBuf;
	NLMSG_OK(nlMsg, msgLen);
	nlMsg = NLMSG_NEXT(nlMsg, msgLen) // will update the msgLen 
    ) {
	bzero(rtInfo, sizeof(struct RouteInfo));

	rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);
	if (rtMsg->rtm_family != AF_INET ||
	    rtMsg->rtm_table != RT_TABLE_MAIN)
	    continue;

	for (
	    len = RTM_PAYLOAD(nlMsg), rtAttr = (struct rtattr *) RTM_RTA(rtMsg);
	    RTA_OK(rtAttr, len);
	    rtAttr = RTA_NEXT(rtAttr, len) // will update the len
	) {
	    switch (rtAttr->rta_type) {
	    case RTA_OIF:
		if (ifname(*(int *) RTA_DATA(rtAttr), rtInfo->ifName) < 0)
		    throw ProbeException("ifname");
		break;

	    case RTA_GATEWAY:
		rtInfo->gateWay.s_addr = *(in_addr_t *)RTA_DATA(rtAttr);
		break;

	    case RTA_PREFSRC:
		rtInfo->srcAddr.s_addr = *(in_addr_t *)RTA_DATA(rtAttr);
		break;

	    case RTA_DST:
		rtInfo->dstAddr.s_addr = *(in_addr_t *)RTA_DATA(rtAttr);

		for (rtInfo->netMask = 0xffffffff,
		     count = 32 - rtMsg->rtm_dst_len;
		     count > 0; count--
		) {
		    rtInfo->netMask = rtInfo->netMask << 1;
		}
		break;
	    }
	}

	if (verbose > 2) {
	    std::cerr << ">>>> routing message <<<<" << std::endl;
	    std::cerr << "source: " << inet_ntoa(rtInfo->srcAddr) << std::endl;
	    std::cerr << "destination: " << inet_ntoa(rtInfo->dstAddr) << std::endl;
	    std::cerr << "gateway: " << inet_ntoa(rtInfo->gateWay) << std::endl;
	    std::cerr << "interface: " << rtInfo->ifName << std::endl;
	    std::fprintf(stderr, "netmask: %08x\n", rtInfo->netMask);
	}

	uint32_t x = htonl(rtInfo->netMask);
	if (
	    // (*((uint32_t *)&addr->s_addr) & rtInfo->netMask) ==
	    (*((uint32_t *)&addr->s_addr) & x) ==
	    *((uint32_t *)&rtInfo->dstAddr.s_addr)
	) {
	    if (
		inet_ntop(AF_INET, &rtInfo->dstAddr, strDestination, INET_ADDRSTRLEN) == NULL ||
		inet_ntop(AF_INET, &rtInfo->gateWay, strGateway, INET_ADDRSTRLEN) == NULL ||
		inet_ntop(AF_INET, (struct in_addr *)&x, strDestinationMask, INET_ADDRSTRLEN) == NULL
	    )
		throw ProbeException("inet_ntop");

	    // std::cerr << "addr = " << inet_ntoa(*addr) << std::endl;
	    // std::cerr << "mask = " << strDestinationMask << std::endl;
	    
	    // if (verbose <= 2)
		break;
	}
    }

    free(rtInfo);
    close(sock);

    return;
    
}
#elif defined _CYGWIN
void ProbeAddressInfo::getRouteInfo(const struct in_addr *addr) throw(ProbeException)
{
    struct RouteInfo *rtihead, *rti;

    if ((rtihead = GetRouteInfo()) == NULL)
	throw ProbeException("GetRouteInfo failed");

    for (rti = rtihead; rti; rti = rti->rt_next) {
	if (
	    (*((uint32_t *)&addr->s_addr) & rti->rt_mask) ==
	    *((uint32_t *)&rti->rt_dest)
	) {
	    if (
		inet_ntop(AF_INET, &rti->rt_dest, strDestination, INET_ADDRSTRLEN) == NULL ||
		inet_ntop(AF_INET, &rti->rt_gateway, strGateway, INET_ADDRSTRLEN) == NULL ||
		inet_ntop(AF_INET, &rti->rt_mask, strDestinationMask, INET_ADDRSTRLEN) == NULL
	    )
		throw ProbeException("inet_ntop");

	    // Don't break until find the last corresponding route
	}
    }

    FreeRouteInfo(rtihead);

    return;
}

#else
void ProbeAddressInfo::getRouteInfo(const struct in_addr *addr) throw(ProbeException)
{
    const char str[] = "unsupported";
    strncpy(strDestination, str, INET_ADDRSTRLEN);
    strncpy(strGateway, str, INET_ADDRSTRLEN);
    strncpy(strDestinationMask, str, INET_ADDRSTRLEN);

    return;
}

#endif


static const char *sock_ntop(const struct sockaddr *sa, char *buf, const ssize_t size)
{
    
    switch(sa->sa_family) {
    case AF_INET:
    {
        struct sockaddr_in *sin;
        sin = (struct sockaddr_in *)sa;
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, size) == NULL)
            return NULL;
        return buf;
    }
#ifdef HAVE_SOCKADDR_DL_STRUCT
    case AF_LINK:
    {
        snprintf(buf, size, "AF_LINK");
        return buf;
    }
#endif
    default:
        snprintf(buf, size, "AF_xxx = %d", sa->sa_family);
        return buf;
    }

    return NULL;
}

static const char *mask_ntop(const struct sockaddr *sa, char *buf, const ssize_t size)
{
    const unsigned char *ptr = (unsigned char *)&sa->sa_data[2];

    uint8_t n;
#ifdef HAVE_SOCKADDR_SA_LEN
    n = sa->sa_len;
#else
    n = sizeof(*sa);
#endif
    
    // fprintf(stderr, "! mask length = %d\n", sa->sa_len);
    switch (n) {
    case 0: 
    {
        snprintf(buf, size, "0.0.0.0");
        return buf;
    }
    case 5:
    {
        snprintf(buf, size, "%d.0.0.0", *ptr);
        return buf;
    }
    case 6:
    {
        snprintf(buf, size, "%d.%d.0.0", *ptr, *(ptr + 1));
        return buf;
    }
    case 7:
    {
        snprintf(buf, size, "%d.%d.%d.0", *ptr, *(ptr + 1), *(ptr + 2));
        return buf;
    }
    case 8:
    {
        snprintf(buf, size, "%d.%d.%d.%d", *ptr, *(ptr + 1), *(ptr + 2),
                 *(ptr + 3));
        return buf;
    }
    default:
        // If sa_len is 255, means the local interface mask, for simplicity, we
        // don't use ioctl to get local interfaces again.
        snprintf(buf, size, "unknown mask");
        return buf;
    }

    return NULL;
}

static const ssize_t ROUNDUP(const ssize_t a, const ssize_t size)
{
    // Round up 'a' to next multiple of 'size', which must be a power of 2
    assert(a > 0 && size > 0);
    if (a & (size - 1))
        return 1 + (a | (size - 1));
 
    return a;
}

static struct sockaddr *NEXT_SA(const struct sockaddr *sa)
{
    ssize_t n;

#ifdef HAVE_SOCKADDR_SA_LEN
    n = sa->sa_len;
#else
    n = sizeof(struct sockaddr);
#endif

    return (
        (struct sockaddr *)
        ((char *)sa + (n ? ROUNDUP(n, sizeof(u_long)) : sizeof(u_long)))
    );
    
}
