#include "FileReading.h"

static size_t countLines(FILE* file) {
    size_t lineCount = 0;
    int    ch;
    DWORD  charCount = 0;

    while ((ch = fgetc(file)) != EOF) {
        charCount++;
        if (ch == '\n') {
            lineCount++;
        }
    }
    lineCount += charCount > 0;

#ifdef _DEBUG
    //printf("\nLine count from server.conf: %d", lineCount);
#endif
    fseek(file, 0, SEEK_SET);

    return lineCount;
}

DWORD readTxtList(const char* dir, Serverlist* list)
{
    FILE*       config;
    const char* errorString = "\nError reading servers.conf";

    fopen_s(&config, dir, "rb");
    if (config == NULL) {
        perror(errorString);
        return ERROR_FT_READ_FAILURE;
    }

    const size_t lineCount = countLines(config);
    list->length = lineCount;

    list->list = (WCHAR*)calloc(SERVERNAME_LEN * lineCount, sizeof(WCHAR));
    char* temp = (char*)malloc(sizeof(char) * SERVERNAME_LEN * lineCount);
    if (temp == NULL || list->list == NULL) {
        // failed to alloc, let's just crash
        fclose (config);
        exit   (1);
    }

    for (DWORD i = 0; i < lineCount; i++) {
        DWORD index = i * SERVERNAME_LEN;
        fgets      (&temp[index], SERVERNAME_LEN - 1, config);
        widenChars (&temp[index], &list->list[index], SERVERNAME_LEN);
    }
    free((char*)temp);
    int i = 0;
    for (DWORD y = 0; y < list->length; y++) {
        truncateWideString(&list->list[y * SERVERNAME_LEN], SERVERNAME_LEN);
    }
    fclose(config);
    return 0;
}
DWORD readTxtListShort(const char* dir, Switchlist* list)
{
    FILE* config;
    const char* errorString = "\nError reading servers.conf";

    fopen_s(&config, dir, "rb");
    if (config == NULL) {
        perror(errorString);
        return ERROR_FT_READ_FAILURE;
    }

    const size_t lineCount = countLines(config);
    list->length = lineCount;

    list->list = (char*)calloc(SERVERNAME_LEN * lineCount, sizeof(char));
    if (list->list == NULL) {
        // failed to alloc, let's just crash
        fclose(config);
        exit(1);
    }
    for (DWORD i = 0; i < lineCount; i++) {
        DWORD index = i * SERVERNAME_LEN;
        fgets(&list->list[index] , SERVERNAME_LEN - 1, config);
    }
    int i = 0;
    for (DWORD y = 0; y < list->length; y++) {
        truncateString(&list->list[y * SERVERNAME_LEN], SERVERNAME_LEN);
    }
    fclose(config);
    return 0;
}
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c