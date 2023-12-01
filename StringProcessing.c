#include "StringProcessing.h"

int findCHARSubstring(const char* substring, const char* string, const char stopChar)
{
    DWORD hits  = 0;
    DWORD index = 0;

    if (substring[0] == '\0') {
        return -1;
    }

    while (string[index] != stopChar){
		while (substring[hits] == string[index + hits]){
            if (substring[hits] != '\0' && string[index + hits] != stopChar) {
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
void truncateWideString(WCHAR* stringIn, const DWORD _len)
{
    DWORD index = 0;
    while (index < _len){
        if (stringIn[index] == L' ' || stringIn[index] == L'\n' || stringIn[index] == L'\r'){
            stringIn[index] = L'\0';
            break;
        }
        index++;
    }
    return;
}

void truncateString(char* stringIn, const DWORD _len)
{
    DWORD index = 0;
    while (index < _len){
        if (stringIn[index] == ' ' || stringIn[index] == '\n' || stringIn[index] == '\r'){
            stringIn[index] = '\0';
            break;
        }
        index++;
    }
    return;
}

void getPassword(char* password, int maxLength) 
{
    int  i = 0;
    char ch;

    while (1){
        ch = _getch(); // Read a character without echoing
        if (ch == '\r' || ch == '\n') { // Check for Enter key
            password[i] = '\0'; // Null terminate the password string
            break;
        }
        else if (ch == '\b' && i > 0) { // Handle backspace
            printf("\b \b"); // Erase the character from display
            i--;
        }
        else if (i < maxLength - 1) { // Store the character in the password if within limits
            password[i] = ch;
            printf("*"); // Print '*' to show something's being typed
            i++;
        }
    }
}

void getIPfromString(const unsigned char* input, DWORD* output, DWORD *mask, DWORD length)
{
    unsigned char ipMask[4]  = { 0 };
    unsigned char ip[4]      = { 0 };
    unsigned char temp[5]    = { 0 };
    int           tempFigure = 0;
    int           figure     = 3;
    for (int i = 0; i < length; i++){
        if (input[i] != '.' && input[i] != 0){
            temp[tempFigure] = input[i];
            tempFigure++;
        }
        else{
            ip[figure] = atoi(temp);
            ipMask[figure] = 0xff;
            tempFigure = 0;
            memset(temp, 0, sizeof(temp));
            figure--;
        }
        if (input[i] == 0 || figure < 0 || tempFigure > 4){
            break;
        }
    }
    *output = *((DWORD*)ip);
    *mask = *((DWORD*)ipMask);
}

// TODO: length unused
void getMACfromString(const unsigned char* input, BYTE *output, DWORD length)
{
	for (int i = 0; i < MAC_ADDRESS_LENGTH; i++){
		int result = sscanf_s(&input[2 * i], "%2hhx", &output[i], sizeof(output[i]));
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
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
