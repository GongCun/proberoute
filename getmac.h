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
    
/* 
 * Fill MacAddress in buf and Return Length:
 *   >=  0: MacAddress Length
 *    = -1: Not found address
 *    = -2: other error
 */
int getmac(const char *destip, unsigned char *buf);
int getmacByDevice(const char *device, unsigned char *buf);

struct RouteInfo *GetRouteInfo(void);
void FreeRouteInfo(struct RouteInfo *rtihead);

#endif
