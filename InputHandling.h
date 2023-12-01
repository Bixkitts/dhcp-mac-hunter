#ifndef MACHUNT_INPUT_HANDLING
#define MACHUNT_INPUT_HANDLING

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "DHCP_Stuff.h"
#include "SSH_Stuff.h"

// Pointer to string and the max length to dereference
typedef void (*inputHandlerFunction)(const char*, char*, DWORD);

typedef enum inputType
{
	INPUT_TYPE_UNDEFINED,
	INPUT_TYPE_REFRESH,
	INPUT_TYPE_MAC,
	INPUT_TYPE_IP,
	INPUT_TYPE_SWITCHLIST,
	INPUT_TYPE_COUNT
}inputType;

// Main input handler dispatch function
DWORD handleInput       (char* input, char* output, DWORD length);
// input handler subroutines
void  undefinedHandler  (const char* input, char* output, DWORD length);
void  refreshHandler    (const char* input, char* output, DWORD length);
void  MACHandler        (const char* input, char* output, DWORD length);
void  IPHandler         (const char* input, char* output, DWORD length);
// Expects an IP address and lists all the machines
// on that switch
void  switchListHandler (const char* input, char* output, DWORD length);

#endif
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c