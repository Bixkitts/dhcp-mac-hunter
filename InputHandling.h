#ifndef MACHUNT_INPUT_HANDLING
#define MACHUNT_INPUT_HANDLING

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "DHCP_Stuff.h"
#include "SSH_Stuff.h"

// Main input handler dispatch function, expects a null-terminated string
int   handleInput          (const char* userInputString);

// Prompts the user for a password
// and produces a null terminated string
void  getPassword          (char* outString, 
	                        const int maxLength);
// Same as getPassword but the input text isn't hidden
void  getInputString       (char* outString,
	                        const int maxLength);
#endif
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c