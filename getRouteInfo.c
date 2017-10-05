#include "ProbeRoute.hpp"

static struct sockaddr *NEXT_SA(const struct sockaddr *sa);
static const char *sock_ntop(const struct sockaddr *sa, char *buf, const ssize_t size);
static const char *mask_ntop(const struct sockaddr *sa, char *buf, const ssize_t size);

void ProbeAddressInfo::getRouteInfo() throw(ProbeException)
{
    int sockfd;
    struct rt_msghdr *rtm;
    struct sockaddr *sa, *rti_info[RTAX_MAX];
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
    rtm->rtm_msglen = sizeof(struct rt_msghdr) + foreignAddrLen;
    // rtm->rtm_msglen = sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in);
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_type = RTM_GET;
    rtm->rtm_addrs = RTA_DST;
    rtm->rtm_pid = pid = getpid();
    rtm->rtm_seq = SEQ;

    std::cerr << "BUFLEN = " << BUFLEN << std::endl;
    std::cerr << "size of rt_msghdr = " << sizeof(struct rt_msghdr) << std::endl;
    std::cerr << "rtm_msglen = " << rtm->rtm_msglen << std::endl;

    // struct sockaddr_in *sin;
    // sin = (struct sockaddr_in *)(rtm + 1);
    // sin->sin_len = sizeof(struct sockaddr_in);
    // sin->sin_family = AF_INET;
    // if (inet_pton(AF_INET, host, &sin->sin_addr) != 1)
        // throw ProbeException("inet_pton");
    
    memcpy((char *)(rtm + 1), (char *)&foreignAddr, foreignAddrLen);
    
    if (write(sockfd, rtm, rtm->rtm_msglen) != rtm->rtm_msglen) {
        throw ProbeException("write rtm");
    }
    
    do {
        if ((n = read(sockfd, rtm, BUFLEN)) < 0)
            throw ProbeException("read rtm");
    } while (rtm->rtm_type != RTM_GET ||
             rtm->rtm_seq != SEQ ||
             rtm->rtm_pid != pid);

    std::cerr << "n = " << n << std::endl;

    rtm = (struct rt_msghdr *)buf;
    sa = (struct sockaddr *)(rtm + 1);

    for (int i = 7; i >= 0; i--)
        std::cerr << ((rtm->rtm_addrs >> i) & 1);
    std::cerr << std::endl;
    
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

    std::cerr << "! outside MASK !\n";
    if (sa = rti_info[RTAX_NETMASK]) {
        std::cerr << "! inside MASK !\n";
        if (mask_ntop(sa, strDestinationMask, sizeof(strDestinationMask)) == NULL)
            throw ProbeException("mask_ntop strDestinationMask");
    }

    free(buf);
}

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
        std::snprintf(buf, size, "AF_LINK");
        return buf;
    }
#endif
    default:
        std::snprintf(buf, size, "unknown AF_xxx: %d",
                      sa->sa_family);
        return buf;
    }

    return NULL;
}

static const char *mask_ntop(const struct sockaddr *sa, char *buf, const ssize_t size)
{
    const char *ptr = &sa->sa_data[2];
    
    switch (sa->sa_len) {
    case 0: 
    {
        std::snprintf(buf, size, "a.0.0.0.0");
        return buf;
    }
    case 5:
    {
        std::snprintf(buf, size, "%d.0.0.0", *ptr);
        return buf;
    }
    case 6:
    {
        std::snprintf(buf, size, "%d.%d.0.0", *ptr, *(ptr + 1));
        return buf;
    }
    case 7:
    {
        std::snprintf(buf, size, "%d.%d.%d.0", *ptr, *(ptr + 1), *(ptr + 2));
        return buf;
    }
    case 8:
    {
        std::snprintf(buf, size, "%d.%d.%d.%d", *ptr, *(ptr + 1), *(ptr + 2),
                 *(ptr + 3));
        return buf;
    }
    default:
        std::snprintf(buf, size, "unknown mask");
        return buf;
    }

    return NULL;
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

static const ssize_t ROUNDUP(const ssize_t a, const ssize_t size)
{
    // Round up 'a' to next multiple of 'size', which must be a power of 2
    assert(a > 0 && size > 0);
    if (a & (size - 1))
        return 1 + (a | size - 1);
 
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

