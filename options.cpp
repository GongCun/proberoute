#include "ProbeRoute.hpp"
#include <popt.h>

// don't start from zero
enum { OPT_HELP = 1000, OPT_PROTO, OPT_SERV, OPT_DEV, OPT_SRCIP,
       OPT_SYN, OPT_ACK, OPT_PUSH, OPT_NULL, OPT_FIN, OPT_XMAS,
       OPT_ECHO, OPT_ECHOREPLY, OPT_TSTAMP, OPT_TSTAMPREPLY, OPT_GATEWAY,
       OPT_TCP, OPT_UDP, OPT_ICMP, OPT_ALL, OPT_LIST
};

static void usage()
{
#define P(s) std::cerr << s << std::endl
#include "usage.h"
#undef P
    exit(1);
}


static struct poptOption po[] = {
    // longName, shortName, argInfo, argPtr, value, descrip, argDesc
    { "verbose",      'v',  POPT_ARG_NONE,   0,          'v',             NULL, NULL },
    { "help",         'h',  POPT_ARG_NONE,   0,          OPT_HELP,        NULL, NULL },
    { NULL,           'P',  POPT_ARG_STRING, 0,          OPT_PROTO,       NULL, NULL },
    { "tcp",          '\0', POPT_ARG_NONE,   0,          OPT_TCP,         NULL, NULL },
    { "udp",          '\0', POPT_ARG_NONE,   0,          OPT_UDP,         NULL, NULL },
    { "icmp",         '\0', POPT_ARG_NONE,   0,          OPT_ICMP,        NULL, NULL },
    { "all",          'A',  POPT_ARG_NONE,   0,          OPT_ALL,         NULL, NULL },
    { "port",         'p',  POPT_ARG_STRING, 0,          OPT_SERV,        NULL, NULL },
    { "source-port",  'g',  POPT_ARG_INT,    &srcport,   0,               NULL, NULL },
    { "source-ip",    'S',  POPT_ARG_STRING, 0,          OPT_SRCIP,       NULL, NULL },
    { NULL,           'i',  POPT_ARG_STRING, 0,          OPT_DEV,         NULL, NULL },
    { NULL,           'q',  POPT_ARG_INT,    &nquery,    0,               NULL, NULL },
    { NULL,           'w',  POPT_ARG_INT,    &waittime,  0,               NULL, NULL },
    { NULL,           'f',  POPT_ARG_INT,    &firstttl,  0,               NULL, NULL },
    { NULL,           'm',  POPT_ARG_INT,    &maxttl,    0,               NULL, NULL },
    { "frag-size",    'F',  POPT_ARG_INT,    &fragsize,  0,               NULL, NULL },
    { "mtu",          's',  POPT_ARG_INT,    &mtu,       0,               NULL, NULL },
    { "conn",         '\0', POPT_ARG_VAL,    &conn,      1,               NULL, NULL },
    { "syn",          '\0', POPT_ARG_NONE,   0,          OPT_SYN,         NULL, NULL },
    { "ack",          '\0', POPT_ARG_NONE,   0,          OPT_ACK,         NULL, NULL },
    { "push",         '\0', POPT_ARG_NONE,   0,          OPT_PUSH,        NULL, NULL },
    { "null",         '\0', POPT_ARG_NONE,   0,          OPT_NULL,        NULL, NULL },
    { "fin",          '\0', POPT_ARG_NONE,   0,          OPT_FIN,         NULL, NULL },
    { "xmas",         '\0', POPT_ARG_NONE,   0,          OPT_XMAS,        NULL, NULL },
    { "badsum",       '\0', POPT_ARG_VAL,    &badsum,    1,               NULL, NULL },
    { "badlen",       '\0', POPT_ARG_VAL,    &badlen,    1,               NULL, NULL },
    { "echo",         'e',  POPT_ARG_NONE,   0,          OPT_ECHO,        NULL, NULL },
    { "echo-reply",   '\0', POPT_ARG_NONE,   0,          OPT_ECHOREPLY,   NULL, NULL },
    { "tstamp",       't',  POPT_ARG_NONE,   0,          OPT_TSTAMP,      NULL, NULL },
    { "tstamp-reply", '\0', POPT_ARG_NONE,   0,          OPT_TSTAMPREPLY, NULL, NULL },
    { "source-route", 'j',  POPT_ARG_STRING, 0,          OPT_GATEWAY,     NULL, NULL },
    { "list",         'l',  POPT_ARG_NONE,   0,          OPT_LIST,        NULL, NULL },
    { NULL,           '\0', POPT_ARG_NONE,   NULL,       0,               NULL, NULL }
};

static void gatewayInit()
{
    optptr = ipopt;
    *optptr++ = IPOPT_NOP;	  // no operation
    *optptr++ = IPOPT_LSRR;	  // loose source route
    *optptr++ = 3;		  // options length
    *optptr++ = 4;		  // ptr position

    return;
}

static void Push_back(int i)
{
    if (std::find(protoVec.begin(), protoVec.end(), i) == protoVec.end())
	protoVec.push_back(i);
}


int parseOpt(int argc, char **argv, std::string& msg)
{
    const char *arg;
    poptContext pc;
    int opt;
    int n = 0;

    if (argc < 2)
	usage();

    pc = poptGetContext(NULL, argc, (const char **)argv, po, 0);

    while ((opt = poptGetNextOpt(pc)) != -1)
	switch (opt){
        case OPT_PROTO:
            arg = poptGetOptArg(pc);
            if (!strcmp(arg, "TCP"))
		Push_back(IPPROTO_TCP);
            else if (!strcmp(arg, "UDP"))
                Push_back(IPPROTO_UDP);
            else if (!strcmp(arg, "ICMP"))
		Push_back(IPPROTO_ICMP);
            else {
		msg = "unknown protocol: ";
		msg += arg;
		return -1;
	    }
            break;

	case OPT_TCP:
	    Push_back(IPPROTO_TCP);
	    break;

	case OPT_UDP:
	    Push_back(IPPROTO_UDP);
	    break;

	case OPT_ICMP:
	    Push_back(IPPROTO_ICMP);
	    break;

        case OPT_ALL:
            Push_back(IPPROTO_TCP);
            Push_back(IPPROTO_UDP);
            Push_back(IPPROTO_ICMP);
            break;

        case OPT_SRCIP:
            srcip = poptGetOptArg(pc);
            break;

        case OPT_SERV:
            service = poptGetOptArg(pc);
            break;

        case OPT_DEV:
            device = poptGetOptArg(pc);
            break;
            
	case OPT_SYN:
	    tcpFlags = TH_SYN;
	    break;

	case OPT_ACK:
	    tcpFlags = TH_ACK;
	    break;

	case OPT_PUSH:
	    tcpFlags = TH_PUSH;
	    break;

	case OPT_NULL:
	    tcpFlags = 0;
	    break;

	case OPT_FIN:
	    tcpFlags = TH_FIN;
	    break;

	case OPT_XMAS:
	    tcpFlags = TH_FIN | TH_PUSH | TH_URG;
	    break;

        case OPT_ECHO:
            icmpFlags = ICMP_ECHO;
            break;

        case OPT_ECHOREPLY:
            icmpFlags = ICMP_ECHOREPLY;
            break;

        case OPT_TSTAMP:
            icmpFlags = ICMP_TSTAMP;
            break;

        case OPT_TSTAMPREPLY:
            icmpFlags = ICMP_TSTAMPREPLY;
            break;

	case OPT_HELP:
	    usage();

	case 'v':
	    verbose++;
	    break;

        case OPT_GATEWAY:
            arg = poptGetOptArg(pc);
	    if (!optptr)
		gatewayInit();
	    if (++n > MAX_GATEWAY) {
		msg = "too many source routes";
		return -1;
	    }
	    if (setAddrByName(arg, (struct in_addr *)optptr) < 0) {
		msg = "can't parse host ";
		msg += arg;
		return -1;
	    }
	    optptr += sizeof(struct in_addr);
	    break;

	case OPT_LIST:
	    listDevice = true;
	    return 0;

	default:
	    msg = poptBadOption(pc, POPT_BADOPTION_NOALIAS);
	    msg += ": ";
	    msg += poptStrerror(opt);
            return -1;
	}

    if ((host = poptGetArg(pc)) == NULL) {
	msg = "missing host argument";
        return -1;
    }

    if (poptPeekArg(pc) != NULL)
        service = poptGetArg(pc);

    // Default protocol is TCP
    if (protoVec.empty())
	protoVec.push_back(IPPROTO_TCP);

    return 0;
}
    
