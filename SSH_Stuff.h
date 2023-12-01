#ifndef MACHUNT_SSH_STUFF
#define MACHUNT_SSH_STUFF
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#define LIBSSH_STATIC 1
#include <libssh/libssh.h>

#include "StringProcessing.h"
#include "Defines.h"
#include "DHCP_Stuff.h"

/* Holds the MAC in string format*/
typedef struct switchPort_S
{
	char           portString [32];
	DHCPClientList clients    [256];
	int            clientCount;
}switchPort_T, *switchPort;

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
	                         switchPort* outBuffer);
void printSwitchPortBuffer  (switchPort buffer);

#endif
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c