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

typedef struct Serverlist
{
	DWORD  length;
	WCHAR* list;
} Serverlist;

typedef struct DHCPClientList
{
	LPDHCP_CLIENT_INFO_ARRAY_VQ *data;
	DWORD                        count;
	// The MAC address string of a search ends up here
	// if nothing is found in DHCP
	BYTE                         errorMAC[16];
} DHCPClientList;

// Maybe I should use access functions instead!!
extern Serverlist     servers;
extern DHCPClientList clients;
extern DHCPClientList foundClients;

DWORD initialiseDHCP               ();
void  cleanupDHCP                  ();
void  printClients                 (const DHCPClientList clients);

// Allocation for a shallow copy of DHCP ClientList
// This is disgusting
void  allocateShallowDstClientList (DHCPClientList* list);
void  freeShallowDstClientList     (DHCPClientList* list);

// Looks at how many characters the user typed in for a MAC
// address and determines the length of the address for
// the purposes of substring MAC search.
// The user input needs to be read as opposed to the
// parsed MAC address, since string delimiters like \0 and \n
// are all valid bytes in a MAC address.
DWORD getLengthFromInputMAC        (const char* input, const DWORD maxLen);
// Searches an existing loaded list for a MAC address
void  searchClientListForMAC       (const BYTE *MAC, const DWORD inputLength, const DHCPClientList *clients, DHCPClientList *results);
void  searchClientListForIP	       (const DWORD MAC,const DWORD ipMask, const DHCPClientList *clients, DHCPClientList *results);
// Retrieves list of clients from all subnets on a server
DWORD getAllClientsFromDHCPServers (const Serverlist *servers, DHCPClientList *list);
// Reads user input and creates a MAC address from it
void  cleanupUserList              (DHCPClientList* list);

#endif
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
