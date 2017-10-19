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
static DWORD GetMacAddress(unsigned char * , struct in_addr ); 
 
//Loads from Iphlpapi.dll
typedef DWORD (WINAPI* psendarp)(struct in_addr DestIP, struct in_addr SrcIP, PULONG pMacAddr, PULONG PhyAddrLen );
typedef DWORD (WINAPI* pgetadaptersinfo)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen );
 
psendarp SendArp;
pgetadaptersinfo GetAdaptersInfo;
 
int getmac(const char *addr, unsigned char *macbuf) 
{
    /* printf("addr: %s\n", addr); */

    WSADATA firstsock;
     
    if (WSAStartup(MAKEWORD(2,2),&firstsock) != 0) 
    {
        fprintf(stderr, "\nFailed to initialise winsock.");
        fprintf(stderr, "\nError Code : %d", WSAGetLastError());
        return -1;   //Return -1 on error
    }
 
    struct in_addr gateway;
        
    HINSTANCE hDll = LoadLibrary("iphlpapi.dll");
         
    GetAdaptersInfo = (pgetadaptersinfo)GetProcAddress(hDll, "GetAdaptersInfo");
    if(GetAdaptersInfo == NULL)
    {
        fprintf(stderr, "Error in iphlpapi.dll %d", GetLastError());
        return -1;
    }

    SendArp = (psendarp)GetProcAddress(hDll,"SendARP");
     
    if(SendArp==NULL)
    {
        fprintf(stderr, "Error in iphlpapi.dll %d", GetLastError());
        return -1;
    }


    /* get gateway IP address */
    DWORD dwRetVal = 0, ret = 0;
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    UINT i;

    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
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
            /* printf("IP: %s\n", pAdapter->IpAddressList.IpAddress.String); */
            if (strcmp(addr, pAdapter->IpAddressList.IpAddress.String) == 0) {
                if (pAdapter->Type != MIB_IF_TYPE_ETHERNET &&
                    pAdapter->Type != IF_TYPE_IEEE80211
                ) {
                    printf("not support type %d\n", pAdapter->Type);
                    return -1; /* only support ethernet */
                }

                gateway.s_addr = inet_addr(pAdapter->GatewayList.IpAddress.String);
                if ((ret = GetMacAddress(macbuf, gateway)) != NO_ERROR) {
		    fprintf(stderr, "GetMacAddress failed with error: %d\n", ret);
		    return -1;
		}
                        
                unsigned char *p = macbuf + 6;
                for (i = 0; i < pAdapter->AddressLength; i++) {
                    *p++ = pAdapter->Address[i];
                }
                // IP type 0x0800
                *p++ = 0x08;
                *p = 0x00;
                free(pAdapterInfo);
                return 0;
            }

            pAdapter = pAdapter->Next;
        }
    }
    else {
	fprintf(stderr, "GetAdaptersInfo failed with error: %d\n", dwRetVal);
        return -1;
    }

    free(pAdapterInfo);
    fprintf(stderr, "can't find the address\n");
    return 1;                   /* return 1 on not found */
}
 
/*
    Get the mac address of a given ip
*/
static DWORD GetMacAddress(unsigned char *mac , struct in_addr destip)
{
    DWORD ret;
    struct in_addr srcip;
    ULONG MacAddr[2];
    ULONG PhyAddrLen = 6;  /* default to length of six bytes */
    int i;
 
    srcip.s_addr=0;
 
    //Send an arp packet
    ret = SendArp(destip , srcip , MacAddr , &PhyAddrLen);
    if (ret == NO_ERROR) {
	//Prepare the mac address
	if(PhyAddrLen) {
	    BYTE *bMacAddr = (BYTE *) & MacAddr;
	    for (i = 0; i < (int) PhyAddrLen; i++) {
		mac[i] = (char)bMacAddr[i];
	    }
	}
    }

    return ret;
    
}

int getarp(const char *destip, unsigned char *buf)
{
    DWORD ret;
    struct in_addr destaddr;
    
    destaddr.s_addr = inet_addr(destip);

    if ((ret = GetMacAddress(buf, destaddr)) == NO_ERROR)
	return 0;
    if (ret == ERROR_NOT_FOUND)
	return 1;

    fprintf(stderr, "GetMacAddress failed with error: %d\n", ret);
    return -1;
}

void winGetRouteInfo(const char *src, char *gateway, char *mask)
{
    /* printf("addr: %s\n", src); */

    WSADATA firstsock;
     
    if (WSAStartup(MAKEWORD(2,2),&firstsock) != 0) 
    {
        return;
    }
 
    HINSTANCE hDll = LoadLibrary("iphlpapi.dll");
         
    GetAdaptersInfo = (pgetadaptersinfo)GetProcAddress(hDll,"GetAdaptersInfo");
    if(GetAdaptersInfo==NULL)
    {
        return;
    }

    /* get gateway IP address */
    DWORD dwRetVal = 0;
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);

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
            if (strcmp(src, pAdapter->IpAddressList.IpAddress.String) == 0) {
                strcpy(gateway, pAdapter->GatewayList.IpAddress.String);
                strcpy(mask, pAdapter->GatewayList.IpMask.String);
                free(pAdapterInfo);
                return;
            }
            pAdapter = pAdapter->Next;
        }
    }

    free(pAdapterInfo);
    return;
}
