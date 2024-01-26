#ifndef MACHUNT_DEFINES
#define MACHUNT_DEFINES

// Max length of server names
#define SERVERNAME_LEN            256
// Buffer size of the input string
// taken from the user.
// should be at least 14 for a MAC address!
#define INPUT_STRING_LENGTH       64
#define SEARCH_STRING_LENGTH      MAC_ADDRESS_LENGTH
// Fixed length for strings that'll be names and labels and such
#define MAX_MESSAGE_STRING_LENGTH 128
#define MAX_LABEL_STRING_LENGTH   64
#define MAX_ADDRESS_STRING_LENGTH 32

// Maximum amount of client arrays
// that will be allocated idk just make the
// number kinda big
#define CLIENTS_MAX               10000

// We need to fill up a bunch of LPDHCP_CLIENT_INFO_ARRAY_VQ addresses
// with DhcpEnumSubnetClientsVQ(). This is the max amount to use.
#define INFO_ARRAY_BUFFER_SIZE    256

// The buffer for ssh output
#define SSH_BUFFER_SIZE           300000
// Buffer size for holding lines printed
// from SSH console
#define SSH_LINE_BUFFER_SIZE      256
// Te, Gi and Fa ports.
#define TYPES_OF_PORTS            3 
// Should never be greater than 9
#define MAX_SWITCHES_IN_STACK     8
#define MAX_PORTS_ON_SWITCH       64
#define MAX_PORTS_IN_STACK        MAX_SWITCHES_IN_STACK*MAX_PORTS_ON_SWITCH
#define MAX_CLIENT_LISTS_PER_PORT 32
#define MAX_CLIENTS_IN_MSARRAY    255

#define COLWIDTH_SMALL            12
#define COLWIDTH_LARGE            18


#endif

//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
