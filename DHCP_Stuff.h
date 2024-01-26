#ifndef MACHUNT_DHCP_STUFF
#define MACHUNT_DHCP_STUFF

#include <winsock2.h>
#include <windows.h>
#include <dhcpsapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "Defines.h"
#include "StringProcessing.h"

typedef struct DHCPClient_T               DHCPClient_T, *DHCPClient;

typedef struct Serverlist
{
	DWORD  length;
	WCHAR* list;
}Serverlist;

typedef struct DHCPClientList_T
{
	DHCPClient_T* clients;
	int           count;
    // Any error messages to do with processing a 
    // client list will be stored here:
    WCHAR         err[MAX_MESSAGE_STRING_LENGTH];
}DHCPClientList_T, *DHCPClientList;

// Maybe I should use access functions instead!!
extern Serverlist       servers;
extern DHCPClientList_T clients;
extern DHCPClientList_T foundClients;

DWORD initialiseDHCP               ();
void  cleanupDHCP                  ();
void  tryPrintClientList                 (const DHCPClientList clients);

// Looks at how many characters the user typed in for a MAC
// address and determines the length of the address for
// the purposes of substring MAC search.
// The user input needs to be read as opposed to the
// parsed MAC address, since string delimiters like \0 and \n
// are all valid bytes in a MAC address.
DWORD getLengthFromInputMAC        (const char* input, const DWORD maxLen);

int   searchClientListForMAC       (const BYTE *MAC, 
	                                const DWORD inputLength, 
	                                const DHCPClientList clients, 
	                                DHCPClientList results);
int   searchClientListForIP	       (const DWORD inIP, 
	                                const DWORD ipMask, 
	                                const DHCPClientList clients, 
	                                DHCPClientList results);
int   searchClientListForString    (const WCHAR* string, 
	                                DHCPClientList clientsIn);
// Retrieves list of clients from all subnets on a server
DWORD getAllClientsFromDHCPServers (const Serverlist *servers, 
	                                DHCPClientList list);
// Reads user input and creates a MAC address from it
void  clearDHCPClientList          (DHCPClientList list);
int   getClientCount               (DHCPClientList);
void  copyDHCPClientList           (const DHCPClientList srcList, 
	                                DHCPClientList dstList);

#endif
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
