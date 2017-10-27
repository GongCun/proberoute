/* Refer to Windows Dev Center GetIpForwardTable function */
#include "getmac.h"
#include <w32api/winsock2.h>
#include <w32api/windows.h>
#include <stdio.h>
#include <w32api/iprtrmib.h>    /* ANY_SIZE, MIB_xxx */
  
//Loads from Iphlpapi.dll
typedef DWORD (WINAPI* pGetIpForwardTable)(
    PMIB_IPFORWARDTABLE pIpForwardTable,
    PULONG pdwSize,
    BOOL bOrder
);
 
pGetIpForwardTable GetIpForwardTable;
 
struct RouteInfo *GetRouteInfo(void)
{
    WSADATA firstsock;
    struct RouteInfo *rti, *rtihead, **rtinext;
     
    if (WSAStartup(MAKEWORD(2,2),&firstsock) != 0) 
    {
        fprintf(stderr, "\nFailed to initialise winsock.");
        fprintf(stderr, "\nError Code : %d", WSAGetLastError());
        return NULL;   //Return NULL on error
    }
 
    HINSTANCE hDll = LoadLibrary("iphlpapi.dll");

    GetIpForwardTable = (pGetIpForwardTable)GetProcAddress(hDll, "GetIpForwardTable");
    if(GetIpForwardTable == NULL)
    {
        fprintf(stderr, "Error in iphlpapi.dll %d", GetLastError());
        return NULL;
    }

    /* variables used for GetIfForwardTable */
    PMIB_IPFORWARDTABLE pIpForwardTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    int i;

    pIpForwardTable = (MIB_IPFORWARDTABLE *) malloc(sizeof (MIB_IPFORWARDTABLE));
    if (pIpForwardTable == NULL) {
        fprintf(stderr, "Error allocating memory\n");
        return NULL;
    }

    if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) ==
        ERROR_INSUFFICIENT_BUFFER) {
        pIpForwardTable = (MIB_IPFORWARDTABLE *) malloc(dwSize);
        if (pIpForwardTable == NULL) {
            fprintf(stderr, "Error allocating memory\n");
            return NULL;
        }
    }

    /* Note that the IPv4 addresses returned in 
     * GetIpForwardTable entries are in network byte order 
     */
    if ((dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, 1)) == NO_ERROR) {
        rtihead = NULL, rtinext = &rtihead;
        
        for (i = 0; i < (int) pIpForwardTable->dwNumEntries; i++) {
            if ((rti = calloc(1, sizeof(struct RouteInfo))) == NULL) {
                fprintf(stderr, "calloc error\n");
                exit(1);
            }
            
            *rtinext = rti;
            rtinext = &rti->rt_next;
            
            rti->rt_dest = (u_long) pIpForwardTable->table[i].dwForwardDest;
            rti->rt_mask = (u_long) pIpForwardTable->table[i].dwForwardMask;
            rti->rt_gateway = (u_long) pIpForwardTable->table[i].dwForwardNextHop;


        }
        free(pIpForwardTable);
        return rtihead;
    }
    else
	fprintf(stderr, "GetIpForwardTable failed with error: %d\n", dwRetVal);

    free(pIpForwardTable);
    return NULL;
}

void FreeRouteInfo(struct RouteInfo *rtihead)
{
    struct RouteInfo *rti, *rtinext;

    for (rti = rtihead; rti; rti = rtinext) {
        rtinext = rti->rt_next;
        free(rti);
    }
    return;
}
