#ifndef MACHUNT_DEFINES
#define MACHUNT_DEFINES

// Max length of server names
#define SERVERNAME_LEN       256
// Buffer size of the input string
// taken from the user.
// should be at least 14 for a MAC address!
#define INPUT_STRING_LENGTH  20
#define SEARCH_STRING_LENGTH 6
// Maximum amount of client arrays
// that will be allocated idk just make the
// number kinda big
#define CLIENTS_MAX          10000

// The buffer for ssh output
#define SSH_BUFFER_SIZE      300000
// Buffer size for holding lines printed
// from SSH console
#define SSH_LINE_BUFFER_SIZE 256


#endif

//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
