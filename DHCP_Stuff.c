#include "DHCP_Stuff.h"
#include "Defines.h"



// This data is laid out this way for 
// easy string-based searching.
typedef struct DHCPClientStrings_T
{
    WCHAR hostname   [MAX_LABEL_STRING_LENGTH];
	WCHAR ip         [MAX_ADDRESS_STRING_LENGTH];
	WCHAR mac        [MAX_ADDRESS_STRING_LENGTH];
}DHCPClientStrings_T, *DHCPClientStrings;

typedef struct DHCPClientNumbers_T
{
    BYTE  mac[MAC_ADDRESS_LENGTH];
    // ip in big-endian format
    DWORD ip;
}DHCPClientNumbers_T, *DHCPClientNumbers;

struct DHCPClient_T
{
    DHCPClientStrings_T strings;
    DHCPClientNumbers_T numbers;
};


Serverlist       servers;
DHCPClientList_T clients      = { 0 };
DHCPClientList_T foundClients = { 0 };

static int   convertMSClientToSaneClient  (const LPDHCP_CLIENT_INFO_VQ MSClient, 
                                           DHCPClient outClient);
static void  copyDHCPClient               (const DHCPClient srcClient, 
                                           DHCPClient dstClient);
static int   initClientList           (DHCPClientList outList,
                                           const int clientCapacity);

DWORD initialiseDHCP()
{
	readTxtList("./servers.conf", &servers);
	getAllClientsFromDHCPServers(&servers, &clients);
    return ERROR_SUCCESS;
}

void cleanupDHCP()
{
    servers.length = 0;
    free                     (servers.list);
	clearDHCPClientList      (&clients);
	clearDHCPClientList      (&foundClients);
}

DWORD getLengthFromInputMAC(const char* input, const DWORD maxLen)
{
    for (DWORD i = 0; i < maxLen; i++){
        if (input[i] == '\n' || input[i] == '\r' || input[i] == 0){
            return i/2;
        }
    }
    return maxLen/2;
}

int searchClientListForIP(const DWORD inIP, 
                          const DWORD ipMask, 
                          const DHCPClientList srcClients, 
                          DHCPClientList outClients)
{
    DHCPClient *clientsToAdd              = (DHCPClient*)calloc(srcClients->count, sizeof(DHCPClient));
    int         amountOfClientsToAdd      = 0;
	DHCPClient  clientBeingChecked        = NULL;
	DWORD       checkMe                   = 0;
	WCHAR       ipString[MAX_ADDRESS_STRING_LENGTH] = { 0 };

    if (clientsToAdd == NULL) {
        fprintf(stderr, "\nMALLOC ERROR");
        exit(1);
    }

    for (DWORD i = 0; i < srcClients->count; i++)
    {
		clientBeingChecked = &srcClients->clients[i];
		checkMe            = (DWORD)(clientBeingChecked->numbers.ip);

		if (((inIP & checkMe) == inIP) && ((inIP ^ checkMe) & ipMask) == 0)
		{
            clientsToAdd[amountOfClientsToAdd] = clientBeingChecked;
            amountOfClientsToAdd++;
		}
    }
    initClientList(outClients, amountOfClientsToAdd);
    if (amountOfClientsToAdd == 0) {
        memset          (ipString, 0, sizeof(ipString));
        getStringFromIP (inIP, ipString, sizeof(ipString)/ sizeof(ipString[0]));
        swprintf        (outClients->err, 
                         sizeof(outClients->err) / sizeof(outClients->err[0]),
                         L"\n  No Clients found for IP: %ls", 
                         ipString);
    }
    else {
        for (int i = 0; i < amountOfClientsToAdd; i++) {
            copyDHCPClient(clientsToAdd[i], &outClients->clients[i]);
        }
    }
    outClients->count = amountOfClientsToAdd;
    free(clientsToAdd);
    return outClients->count;
}

int searchClientListForMAC(const BYTE *MAC, 
                           const DWORD MAC_length, 
                           const DHCPClientList srcClients, 
                           DHCPClientList outClients)
{
    // maybe allocate this on heap (80kb of stacksize)
    DHCPClient *clientsToAdd           = (DHCPClient*)calloc(srcClients->count, sizeof(DHCPClient));
    int         amountOfClientsToAdd   = 0;
	WCHAR       macString[MAX_ADDRESS_STRING_LENGTH] = { 0 };

    if (clientsToAdd == NULL) {
        fprintf(stderr, "\nMALLOC ERROR");
        exit(1);
    }
    // Check the MAC of each client for a byte-wise
    // match and add matches to a list
    for (DWORD i = 0; i < srcClients->count; i++) {
		DHCPClient clientBeingChecked = &srcClients->clients[i];
		BYTE*      checkMe            = clientBeingChecked->numbers.mac;

		if (findBYTESubstring((char*)MAC, MAC_length, (char*)checkMe, MAC_ADDRESS_LENGTH) > -1){
            clientsToAdd[amountOfClientsToAdd] = clientBeingChecked;
            amountOfClientsToAdd++;
        }
    }

    // Clear and allocate the destination list with an appropriate size
    // and copy all matches over.
    // TODO: Compiler _should_ make it fast since it's contiguous, but I
    // may want to check.
    initClientList(outClients, amountOfClientsToAdd);
    if (amountOfClientsToAdd == 0) {
        memset           (macString, 0, sizeof(macString));
        getStringFromMAC (MAC, macString, sizeof(macString)/ sizeof(macString[0]));
        swprintf         (outClients->err, 
                          sizeof(outClients->err) / sizeof(outClients->err[0]),
                          L"\n  No Clients found for MAC: %ls", 
                          macString);
    }
    else {
        for (int i = 0; i < amountOfClientsToAdd; i++) {
            copyDHCPClient(clientsToAdd[i], &outClients->clients[i]);
        }
    }
    outClients->count = amountOfClientsToAdd;
    free(clientsToAdd);
    return outClients->count;
}

int searchClientListForString(const WCHAR* string, DHCPClientList_T* clientsIn)
{
    for (int i = 0; i < clientsIn->count; i++) {
        if (findBYTESubstring(string, wcslen(string) * 2, &clientsIn->clients[i].strings, sizeof(DHCPClientStrings_T)) >= 0) {
            return 1;
        }
    }

    return -1;
}

void tryPrintClientList(const DHCPClientList clients)
{
    if (clients->count < 1) {
        if (stringIsEmpty(clients->err)) {
            wprintf(L"\nError printing DHCPClientList: no data");
        }
        else {
            wprintf(clients->err);
        }
    }
    else {
        // TODO: have a print client function
        for (int i = 0; i < clients->count; i++) {
            DHCPClient client               = &clients->clients[i];
            // create a column to make it pretty
            WCHAR      col1[COLWIDTH_LARGE] = { 0 };
            int        col1size             = COLWIDTH_LARGE - getWStrLen(client->strings.ip);
            for (int i = 0; i < col1size; i++) {
                col1[i] = L' ';
            }
            // no more columns, MAC addresses are fixed length
            wprintf(L"\n %ls%ls%ls    %ls",
                    client->strings.ip, col1,
                    client->strings.mac,
                    client->strings.hostname);
        }
    }
}

DWORD getAllClientsFromDHCPServers(const Serverlist *servers, DHCPClientList outList)
{
    LPDHCP_CLIENT_INFO_ARRAY_VQ *MSClientsArrays      = NULL;
    int                          MSClientArraysCount  = 0;

    const int                    ALL_SUBNETS       = 0;
    DHCP_RESUME_HANDLE           resume            = 0;
    DWORD                        serverClientsRead = 0;
    DWORD                        totalClientsRead  = 0;
    DWORD                        clientsRead       = 0;
    DWORD                        clientsTotal      = 0;
    DWORD                        conversionCounter = 0;

    MSClientsArrays = (LPDHCP_CLIENT_INFO_ARRAY_VQ*)calloc(INFO_ARRAY_BUFFER_SIZE, sizeof(LPDHCP_CLIENT_INFO_ARRAY_VQ));
    if (MSClientsArrays == NULL) {
        fprintf (stderr, "\nError allocating memory");
        exit    (1);
    }
    // First phase: we repeatedly make a DHCP data request where each subsequent
    // request fills the next array of DHCP_CLIENT_INFOs.
    // Afterwards we end up with an array, of arrays of client info.
    for (DWORD j = 0; j < servers->length; j++){
        DWORD status = 0;
        do {
            status            = DhcpEnumSubnetClientsVQ(&servers->list[j * SERVERNAME_LEN], 
                                                        ALL_SUBNETS, 
                                                        &resume, 
                                                        UINT_MAX, 
                                                        &MSClientsArrays[MSClientArraysCount], 
                                                        &clientsRead, 
                                                        &clientsTotal);
            serverClientsRead += clientsRead;
            MSClientArraysCount++;
        } while (status == ERROR_MORE_DATA && MSClientArraysCount < INFO_ARRAY_BUFFER_SIZE);

		wprintf(L"\nTotal found clients on %ls: %d", 
                &servers->list[j * SERVERNAME_LEN], 
                serverClientsRead);
        totalClientsRead += serverClientsRead;
		serverClientsRead = 0;
    }
    initClientList(outList, (int)totalClientsRead);
    outList->count   = (int)totalClientsRead;
    // Second phase: we have our array of arrays, this is disorganised
    // but simply how the data comes from the remote request.
    // We need to "decode" it from arrays of arrays of client info into a more organised
    // data structure befitting of our simple needs.
    for (int i = 0; i < MSClientArraysCount; i++){ // Array of arrays...
        for (int j = 0; j < MSClientsArrays[i]->NumElements; j++) { // Single DHCP_CLIENT_INFO_ARRAY....
            LPDHCP_CLIENT_INFO_VQ clientToConvert = MSClientsArrays[i]->Clients[j];
            DHCPClient            outClient       = &outList->clients[conversionCounter];

            convertMSClientToSaneClient(clientToConvert, outClient);
            conversionCounter++;
			DhcpRpcFreeMemory(clientToConvert);
        }
		DhcpRpcFreeMemory(MSClientsArrays[i]);
    }
    return ERROR_SUCCESS;
}

// This... might get more complex
static void copyDHCPClient(const DHCPClient srcClient, DHCPClient dstClient)
{
    memcpy(dstClient, srcClient, sizeof(DHCPClient_T));
}

void copyDHCPClientList(const DHCPClientList srcList, DHCPClientList dstList)
{
    // -1 in this case because the allocate function adds a +1 margin
    // which suits us all the time, except when copying it's a memory leak.
    initClientList(dstList, srcList->count);
    for (int i = 0; i < srcList->count; i++) {
        copyDHCPClient(&srcList->clients[i], &dstList->clients[i]);
    }
    dstList->count = srcList->count;
    memcpy(dstList->err, srcList->err, sizeof(dstList->err));
}

// Currently crashes the program on malloc failure
static int initClientList(DHCPClientList outList, int clientCapacity)
{
    clearDHCPClientList(outList);
    if (clientCapacity < 1) {
        outList->clients = NULL;
        return 0;
    }
    outList->clients = (DHCPClient_T*)calloc(clientCapacity*2, sizeof(DHCPClient_T));
    if (outList->clients == NULL) {
        fprintf(stderr, "\nClientList MALLOC ERROR");
        exit(1);
        return -1;
    }
    return 0;
}

static int convertMSClientToSaneClient(const LPDHCP_CLIENT_INFO_VQ MSClient, DHCPClient outClient)
{
    DWORD srcIP     = (DWORD)MSClient->ClientIpAddress;
    BYTE* srcMAC    = MSClient->ClientHardwareAddress.Data;
    // numbers
    outClient->numbers.ip  = srcIP;
    memcpy           (outClient->numbers.mac, 
                      srcMAC, 
                      MAC_ADDRESS_LENGTH);
    // strings
    getStringFromIP  (srcIP, 
                      outClient->strings.ip, 
                      MAX_ADDRESS_STRING_LENGTH);
    getStringFromMAC (srcMAC, 
                      outClient->strings.mac, 
                      MAX_ADDRESS_STRING_LENGTH);
    if (MSClient->ClientName != NULL) {
        wcscpy_s (outClient->strings.hostname,
                  sizeof(outClient->strings.hostname) / sizeof(WORD),
                  MSClient->ClientName);
    }
    else {
        wcscpy_s (outClient->strings.hostname, 
                  sizeof(outClient->strings.hostname) / sizeof(WORD),
                  L"NULL");
    }
    return 0;
}

void clearDHCPClientList(DHCPClientList list)
{
    if (list->clients == NULL) {
        list->count = 0;
        return;
    }
    free   (list->clients);
    if (list->err != NULL) {
        memset(list->err, 0, sizeof(list->err));
    }
    list->clients = NULL;
    list->count   = 0;
}
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
