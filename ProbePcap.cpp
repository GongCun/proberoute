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
	netmask = 0xffffff;	  // suppose to be in a C class network
        

    if (netmask == 0) {	          // check again if netmask is still empty
	if (Netmask)
	    netmask = (bpf_u_int32)((struct sockaddr_in *)
				    Netmask)->sin_addr.s_addr; // fetch from deviceInfo
	else
        netmask = 0xffffff;        // suppose to be in a C class network
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
    case 50:			  // DLT_PPP_SERIAL: PPP in HDLC-like framing as per RFC
				  // 1162, or Cisco PPP with HDLC framing, as per section
				  // 4.3.1 of RFC 1547.
    case 104:			  // DLT_C_HDLC: Cisco PPP with HDLC framing.
	ethLen = 4;
	break;

    case 51:			  // DLT_PPP_ETHER: PPPoE, the packet begins with a PPPoE
				  // header, as per RFC 2516.
	ethLen = 14 + 6;	  // Ethernet frame (14-byte) add PPPoE header (6-byte),
				  // _JUST_ PPP session stage.
	break;

    case 105:			  // DLT_IEEE802_11: IEEE 802.11 wireless LAN.
	ethLen = 30;		  // from http://www.rhyshaden.com/wireless.htm
	break;
	
    default:
	msg << "unsupport datalink (" << linkType << ")";
	throw ProbeException(msg.str());
    }

#ifdef _CYGWIN
    pcap_freealldevs(alldevs);
#endif
}

static void sig_alrm(int signo) throw(ProbeException)
{
    siglongjmp(jumpbuf, 1);
#ifdef _AIX
    if (signal(SIGALRM, sig_alrm) == SIG_ERR)
	throw ProbeException("signal error");
#endif
}

// Get double capture (ICMP Raw Socket or Pcap_XXX) by using multithread
enum CapType { WAIT = 999, PCAP = 1, RECV = 2 };
static CapType done = WAIT;
static pthread_cond_t cond;
static pthread_mutex_t mutex;
static int recvfd = -1;
static u_char recvbuf[MAX_MTU];
static int *Len;
static const u_char *Ptr;

struct argPcap 
{
    pcap_t *handle;
    int linkType;
    int *ethLen;
};

static void errExit(const char *str, int err)
{
    std::fprintf(stderr, "%s: %s\n", str, strerror(err));
    exit(1);
}


void *recvPkt(void *arg)
{
    // struct argPcap *argPcap = (struct argPcap *)arg;
    struct sockaddr addr;
    socklen_t addrlen = sizeof(addr);
    int n;
    int err;

    // struct timeval tv;
    // tv.tv_sec = 1, tv.tv_usec = 0;
    // select(0, NULL, NULL, NULL, &tv);
    
    n = recvfrom(recvfd, recvbuf, sizeof(recvbuf), 0, &addr, &addrlen);

    if (err = pthread_mutex_lock(&mutex))
        errExit("pthread_mutex_lock recvPkt()", err);
    
    if (done == WAIT) {
        *Len = n;
        Ptr = recvbuf;
        done = RECV;		  // recvfrom() succeed
    }

    // Nothing to do if have done by captPkt().

    if (err = pthread_mutex_unlock(&mutex))
        errExit("pthread_mutex_unlock recvPkt()", err);

    // We could have reversed these two steps of unlock() and
    // signal(); SUSv3 permits them to be done in either order.
    if (err = pthread_cond_signal(&cond))
	errExit("pthread_cond_signal from recvPkt", err);

    return NULL;
}

void *captPkt(void *arg)
{
    struct argPcap *argPcap = (struct argPcap *)arg;
    static const u_char *ptr, *p;
#ifdef _CYGWIN
    static struct pcap_pkthdr *hdr = NULL;
#else
    static struct pcap_pkthdr hdr;
#endif
    int err;
    int res;
    static pcap_t *handle = argPcap->handle;
    int linkType = argPcap->linkType;
    int *ethLen = argPcap->ethLen;

    // struct timeval tv;
    // tv.tv_sec = 1, tv.tv_usec = 0;
    // select(0, NULL, NULL, NULL, &tv);

#ifdef _CYGWIN
#ifdef _DEBUG
    static pcap_dumper_t *dumpfile = NULL;
    if (dumpfile == NULL &&
	(dumpfile = pcap_dump_open(handle, "./debug.pcap")) == NULL) {
	errExit("pcap_dump_open", errno);
    }
    while ((res = pcap_next_ex(handle, &hdr, &ptr)) >= 0) {
	if (res == 0)
	    continue;		  // timeout elapsed

	fprintf(stderr, "debug success res = %d, hdr->caplen = %d, hdr->len = %d\n",
		res, hdr->caplen, hdr->len);

	// save the packet on the dump file
	pcap_dump((unsigned char *)dumpfile, hdr, ptr);
    }
    pcap_close(handle);
    pcap_dump_close(dumpfile);
#else
    while ((res = pcap_next_ex(handle, &hdr, &ptr)) <= 0) {
	if (res == -1) {
	    fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(handle));
	    exit(1);
	}
	else
	    ;
    }
    
    // fprintf(stderr, "success res = %d, hdr->caplen = %d\n", res, hdr->caplen);
    /*
      _Don't_ change the hdr->caplen, otherwise will trigger the pcap_next_ex code (10038)
      error: Socket operation on nonsocket (WSAENOTSOCK).

      if (!hdr->caplen)
	  hdr->caplen  = GUESS_CAP_LEN;
    */

#endif	// _CYGWIN
#else
    while ((ptr = pcap_next(handle, &hdr)) == NULL) ;
#endif

    if (err = pthread_mutex_lock(&mutex))
        errExit("pthread_mutex_lock captPkt()", err);
    
    if (done == WAIT) {
        // Point-to-Point Protocol
        if (linkType == 9 && *ethLen == 0) {
            // PPP in HDLC-like framing.
            if (*ptr == 0xff && *(ptr + 1) == 0x03)
                *ethLen = 4, p = ptr + 2;
            // Just PPP header (protocol) without framing.
            else
                *ethLen = 2, p = ptr;

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

        // fprintf(stderr, "caplen = %d, ethLen = %d\n", hdr->caplen, *ethLen);
#ifdef _CYGWIN
	if (!hdr->caplen)
#else
	if (!hdr.caplen)
#endif
	    *Len = GUESS_CAP_LEN - *ethLen; // WinPcap don't return the caplen or len
	else
#ifdef _CYGWIN
            *Len = hdr->caplen - *ethLen;
#else
            *Len = hdr.caplen - *ethLen;
#endif

        Ptr = ptr + (*ethLen);
        done = PCAP;		  // pcap_xxx capture succeed
    }

    // Nothing to do if have done by recvPkt().

    if (err = pthread_mutex_unlock(&mutex))
        errExit("pthread_mutex_unlock captPkt()", err);

    if (err = pthread_cond_signal(&cond))
	errExit("pthread_cond_signal from captPkt", err);

    return NULL;
}

const u_char *ProbePcap::nextPcap(int *len)
{
    // static const u_char *ptr;
    pthread_t tid1;
    pthread_t tid2;
    int err;
    static struct argPcap *argPcap = NULL;

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
            errExit("socket recvfd", errno);
    }

#ifdef _DEBUG
    if (signal(SIGALRM, SIG_IGN) == SIG_ERR)
	throw ProbeException("signal ignore error");
#else
    if (signal(SIGALRM, sig_alrm) == SIG_ERR)
	throw ProbeException("signal error");
#endif

    static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
    static pthread_cond_t _cond = PTHREAD_COND_INITIALIZER;
    mutex = _mutex;
    cond = _cond;
    Len = len;
    // if (err = pthread_mutex_init(&mutex, NULL)) {
	// errExit("pthread_mutex_init", err);
    // }

    // if (err = pthread_cond_init(&cond, NULL)) {
	// errExit("pthread_cond_init", err);
    // }

    if (argPcap == NULL &&
	(argPcap = (struct argPcap *)calloc(1, sizeof(struct argPcap))) == NULL) {
	errExit("calloc argPcap", errno);
    }

    // argPcap->len = len, argPcap->ptr = &ptr;
    argPcap->handle = handle, argPcap->linkType = linkType, argPcap->ethLen = &ethLen;
    
    // Make sure that all passed data is thread safe - that it can not
    // be changed by other threads.
    if (err = pthread_create(&tid1, NULL, captPkt, (void *)argPcap)) {
	errExit("pthread_create captPkt", err);
    }

    if (err = pthread_create(&tid2, NULL, recvPkt, NULL)) {
	errExit("pthread_create recvPkt", err);
    }

    // _DON'T_ join the thread, otherwise will be block until the specified
    // thread terminated

    for (;;) {
        if (err = pthread_mutex_lock(&mutex))
            errExit("pthread_mutex_lock nextPcap()", err);
    
        while (done == WAIT)
            pthread_cond_wait(&cond, &mutex);
    
        captureFunc = (done == PCAP) ? "pcap()" :
                      (done == RECV) ? "recv()" : "unknown capture";
        
        /*
        std::cerr << "In nextPcap() captured " << *len << " bytes by "
                  << (done == PCAP ? "pcap()" : "recv()")
                  << std::endl;
        */
        // CapType savedone = done;
        done = WAIT;
        if (*len > 0) {
            pthread_cancel(tid1);
            pthread_cancel(tid2);
            if (err = pthread_mutex_unlock(&mutex))
                errExit("pthread_mutex_unlock nextPcap()", err);
            break;
        }
        else {
            // std::printf("len = %d by %s\n", *len, 
                        // (savedone == PCAP) ? "pcap()" :
                        // (savedone == RECV) ? "recv()" : "unknown captured");

            if (err = pthread_mutex_unlock(&mutex))
                errExit("pthread_mutex_unlock nextPcap()", err);
            
            // errExit("capture error", errno);
        }
        
    }
    

    // clean up and return
    // if (err = pthread_mutex_destroy(&mutex)) {
	// errExit("pthread_mutex_destroy", err);
    // }
    // if (err = pthread_cond_destroy(&cond)) {
	// errExit("pthread_cond_destroy", err);
    // }

    assert(Ptr);
    return Ptr;
}

#if 0
const u_char *ProbePcap::nextPcap(int *len)
{
    const u_char *ptr, *p;
    struct pcap_pkthdr hdr;

    if (signal(SIGALRM, sig_alrm) == SIG_ERR)
	throw ProbeException("signal error");

    while ((ptr = pcap_next(handle, &hdr)) == NULL) ;

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
	    exit(1);
	}
    }

    *len = hdr.caplen - ethLen;

    return ptr + ethLen;
}
#endif
