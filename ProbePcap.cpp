#include "ProbeRoute.hpp"

ProbePcap::ProbePcap(const char *dev,
		     const char *cmd =
		     "icmp[0:1] == 3 or icmp[0:1] == 11 or icmp[0:1] == 12")
    throw(ProbeException) : DEV(dev), CMD(cmd)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 localnet, netmask;
    std::stringstream msg;

    if (dev == NULL)
	throw ProbeException("device name is null");
    
    bzero(errbuf, sizeof(errbuf));

    // specify promiscuous mode
    handle = pcap_open_live(dev, CAP_LEN, CAP_TIMEOUT, 1, errbuf);
    if (handle == NULL)
	throw ProbeException("pcap_open_live", errbuf);

    if (strlen(errbuf))
	std::cerr << "pcap_open_live warning: " << errbuf << std::endl;

    bzero(errbuf, sizeof(errbuf));

    if (pcap_lookupnet(dev, &localnet, &netmask, errbuf) < 0)
	throw ProbeException("pcap_lookupnet", errbuf);

    if (pcap_compile(handle, &bpfCode, (char *)cmd, 0, netmask) < 0)
	throw ProbeException("pcap_compile", pcap_geterr(handle));

    if (pcap_setfilter(handle, &bpfCode) < 0)
	throw ProbeException("pcap_setfilter", pcap_geterr(handle));

    if ((linkType = pcap_datalink(handle)) < 0)
	throw ProbeException("pcap_datalink", pcap_geterr(handle));

    switch (linkType) {
    case 0:			  // DLT_NULL
	ethLen = 4;		  // loopback header is 4 bytes
	break;
    case 1:			  // DLT_EN10MB
	ethLen = 14;		  // IEEE 802.3 (RFC 1042) or Standard Ethernet (RFC 894)
	break;
    case 8:			  // DLT_SLIP	
	ethLen = 16;		  // SLIP header = 16 bytes; see:
                                  // http://www.tcpdump.org/linktypes/LINKTYPE_SLIP.html
	break;
    case 9:			  // DLT_PPP
	ethLen = 0;		  // PPP header length is variable: TCP/IP Illustrated
                                  // Vol.1 Chapter 2.6 PPP: Point-to-Point Protocol
	break;
    default:
	msg << "unsupport datalink (" << linkType << ")";
	throw ProbeException(msg.str());
    }
}

ProbePcap* ProbePcap::_instance = NULL;
ProbePcap* ProbePcap::Instance(const char *dev, const char *cmd) throw(ProbeException)
{
    if (_instance == NULL) {
	_instance = new ProbePcap(dev, cmd);
    }
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

const u_char *ProbePcap::nextPcap(int *len)
{
    const u_char *ptr, *p;
    struct pcap_pkthdr hdr;

    if (signal(SIGALRM, sig_alrm) == SIG_ERR)
	throw ProbeException("signal error");

    while ((ptr = pcap_next(handle, &hdr)) == NULL) ;

    // Point-to-Point Protocol
    p = ptr;
    if (linkType == 9 && ethLen == 0) {
        // PPP in HDLC-like framing.
	if (*ptr == 0xff && *(ptr + 1) == 0x03)
	    ethLen = 4, p += 2;
        // Just PPP header (protocol) without framing.
	else
	    ethLen = 2;

        // Check if it's IPv4 datagram:
        //   IP: 0x0021
        //   Link control data: 0xC021
        //   Network control data: 0x8021
	if (!(*p == 0x00 && *(p + 1) == 0x21)) {
	    std::fprintf(stderr, "Unknown PPP Protocol: 0x%02x%02x\n",
			 *(ptr + 2), *(ptr + 3));
	    exit(1);
	}
    }

    *len = hdr.caplen - ethLen;

    return ptr + ethLen;
}
