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
    case 0:			// loopback header is 4 bytes
	ethLen = 4;
	break;
    case 1:
	ethLen = 14;		// IEEE 802.3 (RFC 1042) or Standard Ethernet (RFC 894)
	break;
    default:
	msg << "unsupport datalink (" << linkType << ")";
	throw ProbeException(msg.str());
    }
}

    

char *ProbePcap::nextPcap(int *len)
{
    char *ptr;
    struct pcap_pkthdr hdr;

    while ((ptr = (char *)pcap_next(handle, &hdr)) == NULL) ;

    *len = hdr.caplen;

    return ptr + ethLen;
}
