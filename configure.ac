#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

##AC_PREREQ([2.69])
AC_INIT([proberoute], [1.0], [gong_cun@bocmacau.com])
AC_CONFIG_SRCDIR([config.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX([xlc++ c++])
AC_PROG_CC([xlc++ c++])

# Checks for libraries.
AC_CHECK_LIB(pcap, pcap_open_live, [], [AC_MSG_ERROR([cannot find libpcap])])
AC_CHECK_LIB(popt, poptGetContext, [], [AC_MSG_ERROR([cannot find libpopt])])
dnl AC_SEARCH_LIBS(pcap_freecode, pcap)
dnl AC_SEARCH_LIBS(pcap_close, pcap)


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h strings.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
##AC_CHECK_HEADER_STDBOOL
##AC_C_INLINE
##AC_TYPE_SIZE_T
##AC_TYPE_SSIZE_T
##AC_TYPE_UINT16_T
##AC_TYPE_UINT32_T

AC_CHECK_MEMBERS([struct ifreq.ifr_mtu], [], [],
[#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
])

AC_CHECK_MEMBERS([struct sockaddr.sa_len], [AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1, [Define to 1 if socket address structures have length fields])], [],
[#include <sys/types.h>
#include <sys/socket.h>
])

AC_CHECK_MEMBERS([struct icmp.icmp_nextmtu], [AC_DEFINE(HAVE_ICMP_NEXTMTU, 1, [Define to 1 if icmp structures have icmp_nextmtu fields])], [],
[#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
])


# Checks for library functions.
##AC_FUNC_MALLOC
AC_CHECK_FUNCS([alarm atexit bzero gettimeofday inet_ntoa memmove select socket strchr strerror])


# Let's see if the system really supports IPv6
AC_MSG_CHECKING(for IPv6 support)
AC_CACHE_VAL(ac_cv_ipv6,
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(void)
{
	int fd;
	struct sockaddr_in6 foo;
	fd = socket(AF_INET6, SOCK_STREAM, 0);
	exit((fd >= 0) ? 0 : 1);
}]])],[ac_cv_ipv6=yes],[ac_cv_ipv6=no],[ac_cv_ipv6=no]))
AC_MSG_RESULT($ac_cv_ipv6)
if test $ac_cv_ipv6 = yes; then
	AC_DEFINE([IPV6], 1, [Define to 1 if the system supports IPv6])
	AC_DEFINE([IPv6], 1, [Define to 1 if the system supports IPv6])
fi

dnl checking for pcap_freecode support
AC_MSG_CHECKING(for pcap_freecode support)
OLD_CFLAGS="$CFLAGS"
OS=`uname -s | tr '[:lower:]' '[:upper:]'`
CFLAGS=-D_$OS
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <pcap.h>
#ifdef _AIX
# include <net/bpf.h>
# include <netinet/if_ether.h>
#else
# include <net/ethernet.h>
#endif
]], [[struct bpf_program bp; pcap_freecode(&bp);]])], [have_pcap_freecode=yes], [have_pcap_freecode=no])
AC_MSG_RESULT($have_pcap_freecode)

CFLAGS="$OLD_CFLAGS"
if test x"$have_pcap_freecode" = x"yes"; then
   AC_DEFINE([HAVE_PCAP_FREECODE], 1, [Define to 1 if the system supports pcap_freecode])
fi

dnl checking for pcap_close support
AC_MSG_CHECKING(for pcap_close support)
OLD_CFLAGS="$CFLAGS"
OS=`uname -s | tr '[:lower:]' '[:upper:]'`
CFLAGS=-D_$OS
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <pcap.h>
#ifdef _AIX
# include <net/bpf.h>
# include <netinet/if_ether.h>
#else
# include <net/ethernet.h>
#endif
]], [[struct pcap_t *p; pcap_close(p);]])], [have_pcap_close=yes], [have_pcap_close=no])
AC_MSG_RESULT($have_pcap_close)

CFLAGS="$OLD_CFLAGS"
if test x"$have_pcap_close" = x"yes"; then
   AC_DEFINE([HAVE_PCAP_CLOSE], 1, [Define to 1 if the system supports pcap_close])
fi

##AC_CONFIG_FILES([Makefile])
AC_OUTPUT