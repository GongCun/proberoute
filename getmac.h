#ifndef _GET_MAC_H
#define _GET_MAC_H

typedef unsigned long u_long;

/* #pragma comment(lib,"ws2_32.lib") //For winsock */
struct RouteInfo 
{
    u_long rt_dest;
    u_long rt_mask;
    u_long rt_gateway;
    struct RouteInfo *rt_next;
};
    

int getmac(const char *, unsigned char *);
int getarp(const char *destip, unsigned char *buf); /* 0: fill the MacAddress of destip to
						     * buf; 1: not found; -1: error */
struct RouteInfo *GetRouteInfo(void);
void FreeRouteInfo(struct RouteInfo *rtihead);

#endif
