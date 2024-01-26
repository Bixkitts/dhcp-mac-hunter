#include "StringProcessing.h"

int findCHARSubstring(const char* substring, const char* string, const char stopChar)
{
    DWORD hits  = 0;
    DWORD index = 0;

    if (substring[0] == '\0') {
        return -1;
    }

    while (string[index] != stopChar && string[index] != '\0') {
		while (substring[hits] == string[index + hits]){
            if (substring[hits] != '\0' && string[index + hits] != stopChar && string[index+hits] != '\0'){
                hits++;
            } 
            else{
                break;
            }
		}
		if (substring[hits] == '\0'){
			return index; // substring found at this index
		}
		hits = 0;
        index++;
    }
    return -1; // substring not found
}

int getStrLen(const char* string)
{
    int  index = 0;

    while (string[index] != '\0') {
        index++;
    }
    return index;
}
int getWStrLen(const WCHAR* string)
{
    int  index = 0;

    while (string[index] != L'\0') {
        index++;
    }
    return index;
}

int findBYTESubstring(const char* substring, const DWORD substringLength, const char* string, const DWORD stringLength)
{
    DWORD hits  = 0;
    DWORD index = 0;

    while (index <= stringLength - substringLength){
		while (substring[hits] == string[index + hits] && hits < substringLength){
			hits++;
		}

        if (hits == substringLength) {
            return index; // substring found
        }
		hits = 0;
        index++;
    }
    return -1; // substring not found
}

// Needed to print IPs
void convertEndian(const DWORD* in, DWORD* out)
{
	*out = ((*in & 0xFF) << 24)    | 
           ((*in & 0xFF00) << 8)   | 
           ((*in & 0xFF0000) >> 8) | 
           ((*in & 0xFF000000) >> 24);
}

void widenChars(const char* _srcStr, WCHAR* _dstStr, DWORD length)
{
    size_t outSize;
    mbstowcs_s(&outSize, (wchar_t*)_dstStr, length, _srcStr, length - 1 );
}

// Reads a string up to the first whitespace and discards everything after that
int truncateWideString(WCHAR* outString, const DWORD maxLength)
{
    DWORD index = 0;
    while (index < maxLength){
        if (outString[index] == L' ' || outString[index] == L'\n' || outString[index] == L'\r'){
            outString[index] = L'\0';
            break;
        }
        index++;
    }
    return index;
}

int truncateString(char* outString, const DWORD maxLength)
{
    DWORD index = 0;
    while (index < maxLength){
        if (outString[index] == ' ' || outString[index] == '\n' || outString[index] == '\r'){
            outString[index] = '\0';
            break;
        }
        index++;
    }
    return index;
}
int getStringFromIP(DWORD ip, WCHAR* outString, size_t maxLen)
{
    DWORD printedIP = 0;
    convertEndian(&ip, &printedIP);
    // TODO: probably faster ways to convert to string format than this
    int result = swprintf_s(outString, 
                            maxLen,
                            L"%u.%u.%u.%u", 
                            (unsigned int)(printedIP & 0xFF), (unsigned int)((printedIP >> 8) & 0xFF), (unsigned int)((printedIP >> 16) & 0xFF), (unsigned int)((printedIP >> 24) & 0xFF));
    return result;
}

int getStringFromMAC(const BYTE* inMAC, WCHAR* outString, size_t maxLen) {
    // TODO: probably faster ways to convert to string format than this
    int result = swprintf_s(outString,
                            maxLen,
                            L"%.02x:%.02x:%.02x:%.02x:%.02x:%.02x",
                            inMAC[0], inMAC[1], inMAC[2], inMAC[3], inMAC[4], inMAC[5]);
    return result;

}

void getIPfromString(const unsigned char* input, DWORD* output, DWORD *mask, DWORD length)
{
    unsigned char ipMask      [4] = { 0 };
    unsigned char ip          [4] = { 0 };
    unsigned char numString   [5] = { 0 };   // The string that will hold each decimal string number
                                             // before conversion to a 1-byte unsigned int
    int           numStringIndex  = 0;
    int           figure          = 3;

    for (int i = 0; i < length; i++){
        if (input[i] != '.' && input[i] != '\0') {
            // Build a string decimal number
            numString[numStringIndex] = input[i];
            numStringIndex++;
        }
        else{
            // We've hit a period or NUL char, convert what we have
            // to a 1-byte unsigned int (in Big-Endian order, where 
            // [figure] starts at 3)
            ip     [figure] = atoi(numString);
            ipMask [figure] = 0xff;
            numStringIndex  = 0;
            memset(numString, 0, sizeof(numString));
            figure--;
        }
        if (input[i] == 0 || figure < 0 || numStringIndex > 3){
            break;
        }
    }
    *output = *((DWORD*)ip);
    *mask   = *((DWORD*)ipMask);
}

// TODO: length unused
void getMACfromString(const unsigned char* input, BYTE *output, DWORD length)
{
	for (int i = 0; i < MAC_ADDRESS_LENGTH; i++){
		int result = sscanf_s(&input[2 * i], "%2hhx", &output[i]);
	}
}

// TODO: maybe I should go to the start of the line
DWORD getLineLength(const char* inBuffer)
{
    DWORD count = 0;
    while (inBuffer[count] != '\0'){
        char c = inBuffer[count];
        if (c != '\n' && c != '\r'){
            count++;
        }
        else{
            break;
        }
    }
    return count;
}

// TODO: I might need to patch this to bring the 
// currentIndex forward again to skip over whitespace
// after bringing it back
DWORD goToStartOfLine(const char* inBuffer, DWORD index)
{
    BOOL newlineHit = FALSE;
    while (index > 0){
        if (inBuffer[index] != '\n' && inBuffer[index] != '\r'){
            index--;
        }
        else{
            newlineHit = TRUE;
            break;
        }
    }
    if (newlineHit){
        index++;
    }
    return index;
}

int goToStartOfNextLine(const char* buffer, DWORD index)
{
    while (buffer[index] != '\0'){
        if (buffer[index] != '\n' && buffer[index] != '\r'){
            index++;
        }
        else{
            break;
        }
    }
	while (buffer[index] != '\0'){
		if (buffer[index] == '\n' || buffer[index] == '\r' || buffer[index] == ' ') {
			index++;
		}
        else if (buffer[index] != '\0'){
			return index;
		}
	}
    return -1; // End of buffer
}

int goToNextChar(const char* buffer, const char c, DWORD index)
{
    while (buffer[index] != c && buffer[index] != '\0') {
        index++;
    }
    if (buffer[index] == c) {
        return index;
    }
    else {
        return -1;
    }
}

BOOL stringIsEmpty(const char* const string)
{
    if (string == NULL) {
        return TRUE;
    }
    else if (string[0] == '\0') {
        return TRUE;
    }
    else {
        return FALSE;
    }
}
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
