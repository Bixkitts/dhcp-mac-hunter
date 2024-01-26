#ifndef MACHUNT_SSH_STUFF
#define MACHUNT_SSH_STUFF
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
// TODO: are we even compiling it statically?
#define LIBSSH_STATIC 1
#include <libssh/libssh.h>

#include "StringProcessing.h"
#include "Defines.h"
#include "DHCP_Stuff.h"

typedef struct SwitchPort_T      SwitchPort_T, *SwitchPort;
typedef struct SwitchPortArray_T SwitchPortArray_T, *SwitchPortArray;

int  sshConnectAuth         (const char* address, 
	                         const char* username, 
	                         const char* password, 
	                         ssh_session outSession);
int  sshSingleRemoteExecute (ssh_session session, 
	                         const char* command, 
	                         char* out);
void cleanupSSH             (ssh_session session);
int  extractSwitchPortData  (const char* inBuffer, 
	                         DWORD inBufferSize, 
	                         SwitchPortArray* outBuffer);
int  sortSwitchArray        (const SwitchPortArray inPortArray, 
	                         SwitchPortArray* outPortArray);
void printSwitchPortArray   (SwitchPortArray buffer);
int  searchSwitchPortArray  (const WCHAR* string,
	                         const DWORD strlen,
	                         const SwitchPortArray inList,
	                         SwitchPortArray* outList);
void deleteSwitchPortArray  (SwitchPortArray* array);

#endif
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c