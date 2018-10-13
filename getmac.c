/*
    Author: Silver Moon ( m00n.silv3r@gmail.com )
     
    Find mac address of a given IP address using iphlpapi

    Updated by Cun Gong refer to Windows Dev Center GetAdaptersInfo function
*/
#include "getmac.h"
#include <w32api/winsock2.h>
#include <w32api/windows.h>
#include <stdio.h>
#include <string.h>             /* strcmp */
#include <w32api/ipifcons.h>    // MIB_IF_TYPE_ETHERNET
  
#define MAX_ADAPTER_NAME_LENGTH 256
#define MAX_ADAPTER_DESCRIPTION_LENGTH 128
#define MAX_ADAPTER_ADDRESS_LENGTH 8
 
//Necessary Structs
typedef struct
{
    char String[4 * 4];
} IP_ADDRESS_STRING, *PIP_ADDRESS_STRING, IP_MASK_STRING, *PIP_MASK_STRING;
 
typedef struct _IP_ADDR_STRING 
{
    struct _IP_ADDR_STRING* Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
} IP_ADDR_STRING , *PIP_ADDR_STRING;
 
typedef struct _IP_ADAPTER_INFO 
{ 
    struct _IP_ADAPTER_INFO* Next; 
    DWORD           ComboIndex; 
    char            AdapterName[MAX_ADAPTER_NAME_LENGTH + 4]; 
    char            Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4]; 
    UINT            AddressLength; 
    BYTE            Address[MAX_ADAPTER_ADDRESS_LENGTH]; 
    DWORD           Index; 
    UINT            Type; 
    UINT            DhcpEnabled; 
    PIP_ADDR_STRING CurrentIpAddress; 
    IP_ADDR_STRING  IpAddressList; 
    IP_ADDR_STRING  GatewayList; 
    IP_ADDR_STRING  DhcpServer; 
    BOOL            HaveWins; 
    IP_ADDR_STRING  PrimaryWinsServer; 
    IP_ADDR_STRING  SecondaryWinsServer; 
    time_t          LeaseObtained; 
    time_t          LeaseExpires; 
} IP_ADAPTER_INFO, *PIP_ADAPTER_INFO;
 
 
//Functions
static DWORD GetMacAddress(unsigned char * , struct in_addr, PULONG); 
 
//Loads from Iphlpapi.dll
typedef DWORD (WINAPI* psendarp)(
    struct in_addr DestIP,
    struct in_addr SrcIP,
    PULONG pMacAddr,
    PULONG PhyAddrLen
);
 
typedef DWORD (WINAPI* pgetadaptersinfo)(
    PIP_ADAPTER_INFO pAdapterInfo,
    PULONG pOutBufLen
);

static psendarp SendArp;
static pgetadaptersinfo GetAdaptersInfo;
static BOOL getMacInit();
static BOOL doInit = FALSE;
 
static BOOL getMacInit()
{
    WSADATA firstsock;
     
    if (WSAStartup(MAKEWORD(2,2),&firstsock) != 0) 
    {
        fprintf(stderr, "\nFailed to initialise winsock.");
        fprintf(stderr, "\nError Code : %d", WSAGetLastError());
        return FALSE;
    }
 
    HINSTANCE hDll = LoadLibrary("iphlpapi.dll");
         
    GetAdaptersInfo = (pgetadaptersinfo)GetProcAddress(hDll, "GetAdaptersInfo");
    if(GetAdaptersInfo == NULL)
    {
        fprintf(stderr, "GetAdaptersInfo error in iphlpapi.dll %d", GetLastError());
        return FALSE;
    }

    SendArp = (psendarp)GetProcAddress(hDll,"SendARP");
    if(SendArp==NULL)
    {
        fprintf(stderr, "SendArp error in iphlpapi.dll %d", GetLastError());
        return FALSE;
            }

    return TRUE;
}
 
/*
    Get the mac address of a given ip
*/
static DWORD GetMacAddress(unsigned char *mac , struct in_addr destip, PULONG pPhyAddrLen)
{
    DWORD ret;
    struct in_addr srcip;
    ULONG MacAddr[2];
    int i;
 
    srcip.s_addr=0;
 
    //Send an arp packet
    ret = SendArp(destip , srcip , MacAddr , pPhyAddrLen);
    if (ret == NO_ERROR) {
	//Prepare the mac address
	if(*pPhyAddrLen) {
	    BYTE *bMacAddr = (BYTE *) & MacAddr;
	    for (i = 0; i < (int)*pPhyAddrLen; i++) {
		mac[i] = (char)bMacAddr[i];
	    }
	}
    }

    return ret;
}

/* Return MacAddress Length:
 *   >=  0: MacAddress Length
 *    = -1: Not found address
 *    = -2: Other error
 */
int getmac(const char *destip, unsigned char *buf)
{
    DWORD ret;
    int PhyAddrLen = 6;         /* default MacAddress length */
    struct in_addr destaddr;
    
    if (!doInit && !(doInit = getMacInit())) {
        return -2;
    }
    
    destaddr.s_addr = inet_addr(destip);

    if ((ret = GetMacAddress(buf, destaddr, (ULONG *)&PhyAddrLen)) == NO_ERROR)
	return PhyAddrLen;

    /*  This ERROR_BAD_NET_NAME error occurs if the destination IPv4
     *  address could not be reached because it is not on the same
     *  subnet or the destination computer is not operating. */
    if (ret == ERROR_NOT_FOUND || ret == ERROR_BAD_NET_NAME)
    return -1;

    fprintf(stderr, "GetMacAddress failed with error: %d\n", ret);
    return -2;
    }
 
/* Return MacAddress Length:
 *   >=  0: MacAddress Length
 *    = -1: Not found address
 *    = -2: Other error
 */
int getmacByDevice(const char *device, unsigned char *buf)
    {
    DWORD dwRetVal = 0;
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    int PhyAddrLen = 6;

    if (!doInit && !(doInit = getMacInit())) {
        return -2;
    }

    pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        fprintf(stderr, "Error allocating memory needed to call GetAdaptersinfo\n");
        exit(1);
    }

    // Make an initial call to GetAdaptersInfo to get
    // the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            fprintf(stderr, "Error allocating memory needed to call GetAdaptersinfo\n");
            exit(1);
        }
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (strcmp(device, pAdapter->AdapterName) == 0) {
                if (pAdapter->Type != MIB_IF_TYPE_ETHERNET &&
                    pAdapter->Type != IF_TYPE_IEEE80211
                ) {
                    printf("not support type %d\n", pAdapter->Type);
                    return -1; /* only support ethernet */
                }

		PhyAddrLen = getmac(pAdapter->IpAddressList.IpAddress.String, buf);
                free(pAdapterInfo);
		return PhyAddrLen;
            }
            pAdapter = pAdapter->Next;
        }
    }
    else {
	fprintf(stderr, "GetAdaptersInfo failed with error: %d\n", dwRetVal);
        return -2;
    }

    free(pAdapterInfo);
    fprintf(stderr, "can't find the address\n");
    return -1;			  /* return -1 on not found */
}
