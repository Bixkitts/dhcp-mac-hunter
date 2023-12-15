#ifndef MACHUNT_STRING_PROCESSING
#define MACHUNT_STRING_PROCESSING

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef MAC_ADDRESS_LENGTH
#define MAC_ADDRESS_LENGTH 6
#endif

// Returns index into string on successful search, and -1 on failure.
// Naive substring search based on null terminator in the substring
// and custom terminator in the string being searched
int   findCHARSubstring    (const char* substring, 
	                        const char* string,
                            const char stopChar);
// Returns index into string on successful search, and -1 on failure.
// This searches based on length rather than null terminator
int   findBYTESubstring    (const char* substring, 
	                        const DWORD substringLength, 
	                        const char* string, 
	                        const DWORD stringLength);
void  convertEndian        (const DWORD* in, 
	                        DWORD* out);
void  widenChars           (const char* _srcStr, 
	                        WCHAR* _dstStr, 
	                        DWORD length);
int   goToNextChar         (const char* buffer,
	                        const char c,
							DWORD index);
int   getStrLen            (const char* string);
// Traverses an array,
// starting at the given memory address, and replaces
// the first whitespace character it encounters with 
// a null terminator 0x00
void  truncateWideString   (WCHAR* stringIn, 
	                        const DWORD _len);
void  truncateString       (char* stringIn, 
	                        const DWORD _len);
// Prompts the user for a password
// and produces a null terminated string
void  getPassword          (char* password, 
	                        int maxLength);
// Starts at the given address and 
// converts an ip string in the format XX.XX.XX.XX
// (up to the first null terminator)
// into a machine readable big-endian 32 bit address.
// The "mask" is the subnet mask for the big-endian 32 bit
// IP, taking effect when a partial IP is given.
void  getIPfromString      (const unsigned char* input, 
	                        DWORD* output, 
	                        DWORD* mask, 
	                        DWORD length);
// Takes a MAC in 12 byte human-written string format,
// converting the 12 byte human-written form into the
// 6 byte machine readable for.
// Seems to be case insensitive.
void  getMACfromString     (const unsigned char* input, 
	                        BYTE* output, 
	                        DWORD length);
// Given a starting address,
// This function counts how many characters there are
// up to and NOT including the first newline character
// that is encountered and returns the number
DWORD getLineLength        (const char* inBuffer);
// Brings an index backwards in the buffer
// to the first character occurring after a newline.
// IMPORTANT: returns the integer index of the
// start of the line
DWORD goToStartOfLine      (const char* inBuffer, 
	                        DWORD index);
// Puts the index at the first non-whitespace character
// after the first newline character it finds.
// Returns -1 if the end of the buffer is encountered
// and 0 on success.
int   goToStartOfNextLine  (const char* buffer, DWORD index);

#endif
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
