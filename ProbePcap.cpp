#include "ProbeRoute.hpp"
#include <pthread.h>
#include <errno.h>
#include <assert.h>

ProbePcap::ProbePcap(const char *dev,
                     const char *cmd =
                     "icmp[0:1] == 3 or icmp[0:1] == 11 or icmp[0:1] == 12")
    throw(ProbeException) : DEV(dev), CMD(cmd)
{
    // std::cerr << "ProbePcap constructor\n";
    
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 localnet, netmask;
    std::stringstream msg;

    if (dev == NULL)
        throw ProbeException("device name is null");
    
    bzero(errbuf, sizeof(errbuf));

#ifdef _CYGWIN
    pcap_if_t *alldevs;
    pcap_if_t *d;
    if (pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        throw ProbeException("pcap_findalldevs_ex", errbuf);
    }
    for (d = alldevs; d; d = d->next) {
        if (strcmp(dev, d->name) == 0) {
            // std::cerr << "d->name = " << d->name << std::endl;
            break;
        }
    }
    if (!d) {
        pcap_freealldevs(alldevs);
        throw ProbeException("pcap_findalldevs_ex: can't find device");
    }
            
    handle = pcap_open_live(
        d->name,                   // name of the device
        CAP_LEN,
        PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
        CAP_TIMEOUT,
        errbuf);
#else
    // specify promiscuous mode
    handle = pcap_open_live(dev, CAP_LEN, 1, CAP_TIMEOUT, errbuf);
#endif

    if (handle == NULL)
        throw ProbeException("pcap_open_live", errbuf);

    if (strlen(errbuf))
        std::cerr << "pcap_open_live warning: " << errbuf << std::endl;

    bzero(errbuf, sizeof(errbuf));

#ifdef _CYGWIN
    // std::cerr << "CYGWIN Netmask\n";
    if (d->addresses) {
        // Retrieve the mask of the first address of the interface
        netmask = (bpf_u_int32) ((struct sockaddr_in *)
                                 (d->addresses->netmask))->sin_addr.s_addr;
    }
    else if (Netmask) {
        netmask = (bpf_u_int32)((struct sockaddr_in *)
                                Netmask)->sin_addr.s_addr; // fetch from deviceInfo
    }
    else
        netmask = 0xffffff;                                // suppose to be in a C class network
        

    if (netmask == 0) {                                    // check again if netmask is still empty
        if (Netmask)
            netmask = (bpf_u_int32)                        // fetch from deviceInfo
                      ((struct sockaddr_in *)Netmask)->sin_addr.s_addr;
        else
            netmask = 0xffffff;                            // suppose to be in a C class network
    }

    if (verbose > 3)
        std::fprintf(stderr, "filter netmask is %s\n",
                     inet_ntoa(*((struct in_addr *)&netmask)));

#else
    if (pcap_lookupnet(dev, &localnet, &netmask, errbuf) < 0)
        throw ProbeException("pcap_lookupnet", errbuf);
#endif

    // std::fprintf(stderr, "pcap() netmask = 0x%08x\n", netmask);

    if (pcap_compile(handle, &bpfCode, (char *)cmd, 1, netmask) < 0)
        throw ProbeException("pcap_compile", pcap_geterr(handle));

    if (pcap_setfilter(handle, &bpfCode) < 0)
        throw ProbeException("pcap_setfilter", pcap_geterr(handle));

    if ((linkType = pcap_datalink(handle)) < 0)
        throw ProbeException("pcap_datalink", pcap_geterr(handle));

    switch (linkType) {
    case 0:              // DLT_NULL
        ethLen = 4;      // loopback header is 4 bytes
        break;
    case 1:              // DLT_EN10MB
        ethLen = 14;     // IEEE 802.3 (RFC 1042) or Standard Ethernet (RFC 894)
        break;
    case 8:              // DLT_SLIP	
        ethLen = 16;		 // SLIP header = 16 bytes; see:
                         // http://www.tcpdump.org/linktypes/LINKTYPE_SLIP.html
        break;
    case 9:              // DLT_PPP
        ethLen = 0;      // PPP header length is variable: TCP/IP Illustrated
                         // Vol.1 Chapter 2.6 PPP: Point-to-Point Protocol
        break;
    case 50:             // DLT_PPP_SERIAL: PPP in HDLC-like framing as per RFC
                         // 1162, or Cisco PPP with HDLC framing, as per section
                         // 4.3.1 of RFC 1547.
    case 104:            // DLT_C_HDLC: Cisco PPP with HDLC framing.
        ethLen = 4;
        break;

    case 51:             // DLT_PPP_ETHER: PPPoE, the packet begins with a PPPoE
                         // header, as per RFC 2516.
        ethLen = 14 + 6; // Ethernet frame (14-byte) add PPPoE header (6-byte),
                         // _JUST_ PPP session stage.
        break;

    case 105:            // DLT_IEEE802_11: IEEE 802.11 wireless LAN.
        ethLen = 30;     // from http://www.rhyshaden.com/wireless.htm
        break;
	
    default:
        msg << "unsupport datalink (" << linkType << ")";
        throw ProbeException(msg.str());
    }

#ifdef _CYGWIN
    pcap_freealldevs(alldevs);
#endif
}

// Setup singleton.
ProbePcap* ProbePcap::_instance = NULL;
ProbePcap* ProbePcap::Instance(const char *dev,
                               const char *cmd) throw(ProbeException)
{
    if (_instance == NULL)
        _instance = new ProbePcap(dev, cmd);
    
    return _instance;
}

static void sig_alrm(int signo) throw(ProbeException)
{
    siglongjmp(jumpbuf, 1);
#ifdef _AIX
    if (signal(SIGALRM, sig_alrm) == SIG_ERR)
        throw ProbeException("signal error");
#endif
}


const u_char *ProbePcap::recvPkt(int *len) throw(ProbeException)
{
    int n;
    struct sockaddr addr;
    socklen_t addrlen = sizeof(addr);
    static int recvfd = -1;
    static u_char recvbuf[MAX_MTU];

    if (recvfd < 0) {
#ifdef _CYGWIN
        // Cygwin _DOESN'T_ support receive data from raw socket. With
        // Winsock, a raw socket can be used with the SIO_RCVALL IOCTL
        // to receive all IP packets through a network interface, the
        // protocol must be set to IPPROTO_IP.
        if ((recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) < 0)
#else
        if ((recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
#endif
            throw ProbeException("socket error");
    }

    while ((n = recvfrom(recvfd, recvbuf, sizeof(recvbuf), 0, &addr, &addrlen)) == -1) {
        if (!(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            throw ProbeException("recvfrom error");
    }

    *len = n;
    return recvbuf;
}

const u_char *ProbePcap::captPkt(int *len) throw(ProbeException)
{
    static const u_char *ptr, *p;
#ifdef _CYGWIN
    static struct pcap_pkthdr *hdr = NULL;
#else
    static struct pcap_pkthdr hdr;
#endif
    int res;

#ifdef _CYGWIN
    while ((res = pcap_next_ex(handle, &hdr, &ptr)) <= 0) {
        if (res == -1) {
            throw ProbeException("pcap_next_ex", pcap_geterr(handle));
        }
    }
#else
    while ((ptr = pcap_next(handle, &hdr)) == NULL) ;
#endif

    
    // Point-to-Point Protocol
    if (linkType == 9 && ethLen == 0) {
        // PPP in HDLC-like framing.
        if (*ptr == 0xff && *(ptr + 1) == 0x03)
            ethLen = 4, p = ptr + 2;
        // Just PPP header (protocol) without framing.
        else
            ethLen = 2, p = ptr;

        // Check if it's IPv4 datagram:
        //   IP: 0x0021
        //   Link control data: 0xC021
        //   Network control data: 0x8021
        if (!(*p == 0x00 && *(p + 1) == 0x21)) {
            std::fprintf(stderr, "Unknown PPP Protocol: 0x%02x%02x\n",
                         *(ptr + 2), *(ptr + 3));
            throw ProbeException("captPkt");
        }
    }

    /*
      _Don't_ change the hdr->caplen like this:

      if (!hdr->caplen)
          hdr->caplen  = GUESS_CAP_LEN;

      Otherwise will trigger the pcap_next_ex code (10038) error: Socket
      operation on nonsocket (WSAENOTSOCK).

    */
#ifdef _CYGWIN
    if (!hdr->caplen)
#else
    if (!hdr.caplen)
#endif
        *len = GUESS_CAP_LEN - ethLen; // WinPcap don't return the caplen or len
    else {
#ifdef _CYGWIN
        *len = hdr->caplen - ethLen;
#else
        *len = hdr.caplen - ethLen;
#endif
    }

    return ptr + ethLen;
}

const u_char *ProbePcap::nextPcap(int *len) throw(ProbeException)
{
    if (signal(SIGALRM, sig_alrm) == SIG_ERR)
        throw ProbeException("signal error");
    
    if (getenv("PROBE_RECV"))
        return recvPkt(len);
    else
        return captPkt(len);
}
