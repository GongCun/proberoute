#include "ProbeRoute.hpp"
#include <popt.h>

// don't start from zero
enum { OPT_HELP = 1000, OPT_PROTO, OPT_SERV, OPT_DEV, OPT_SRCIP,
       OPT_SYN, OPT_ACK, OPT_PUSH, OPT_NULL, OPT_FIN, OPT_XMAS,
       OPT_ECHO, OPT_ECHOREPLY, OPT_TSTAMP, OPT_TSTAMPREPLY
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
    { "tcp",          '\0', POPT_ARG_VAL,    &protocol,  IPPROTO_TCP,     NULL, NULL },
    { "udp",          '\0', POPT_ARG_VAL,    &protocol,  IPPROTO_UDP,     NULL, NULL },
    { "icmp",         '\0', POPT_ARG_VAL,    &protocol,  IPPROTO_ICMP,    NULL, NULL },
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
    { NULL,           '\0', POPT_ARG_NONE,   NULL,       0,               NULL, NULL }
};


int parseOpt(int argc, char **argv, std::string& msg)
{
    const char *arg;
    poptContext pc;
    int opt;

    if (argc < 2)
	usage();

    pc = poptGetContext(NULL, argc, (const char **)argv, po, 0);

    while ((opt = poptGetNextOpt(pc)) != -1)
	switch (opt){
        case OPT_PROTO:
            arg = poptGetOptArg(pc);
            if (!strcmp(arg, "TCP"))
                protocol = IPPROTO_TCP;
            else if (!strcmp(arg, "UDP"))
                protocol = IPPROTO_UDP;
            else if (!strcmp(arg, "ICMP"))
                protocol = IPPROTO_ICMP;
            else {
		msg = "unknown protocol: ";
		msg += arg;
		return -1;
	    }
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
	    flags = TH_SYN;
	    break;

	case OPT_ACK:
	    flags = TH_ACK;
	    break;

	case OPT_PUSH:
	    flags = TH_PUSH;
	    break;

	case OPT_NULL:
	    flags = 0;
	    break;

	case OPT_FIN:
	    flags = TH_FIN;
	    break;

	case OPT_XMAS:
	    flags = TH_FIN | TH_PUSH | TH_URG;
	    break;

        case OPT_ECHO:
            flags = ICMP_ECHO;
            break;

        case OPT_ECHOREPLY:
            flags = ICMP_ECHOREPLY;
            break;

        case OPT_TSTAMP:
            flags = ICMP_TSTAMP;
            break;

        case OPT_TSTAMPREPLY:
            flags = ICMP_TSTAMPREPLY;
            break;

	case OPT_HELP:
	    usage();

	case 'v':
	    verbose++;
	    break;

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

    return 0;
}
    
