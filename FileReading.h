#ifndef MACHUNT_FILEREADING
#define MACHUNT_FILEREADING

#include <winsock2.h>
#include <windows.h>
#include "StringProcessing.h"
#include "DHCP_Stuff.h"
#include "defines.h"

// Read servers out of servers.conf file
DWORD readTxtList (const char* dir, 
	               Serverlist* list);

#endif
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
