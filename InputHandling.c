#include "InputHandling.h"

#define INPUT_TOKEN_LENGTH 32
#define MAX_INPUT_TOKENS   8

// Pointer to string and the max length to dereference
typedef void (*inputHandlerFunction)(InputTokenArray);

typedef enum inputType
{
	INPUT_TYPE_UNDEFINED,
	INPUT_TYPE_REFRESH,
	INPUT_TYPE_MAC,
	INPUT_TYPE_IP,
	INPUT_TYPE_SWITCHLIST,
	INPUT_TYPE_DEADPORT_LIST,
	INPUT_TYPE_HELP,
	INPUT_TYPE_COUNT
}InputType;

typedef struct InputToken_T
{
    char   string[INPUT_TOKEN_LENGTH];
    DWORD  length;
}InputToken_T, *InputToken;

typedef struct InputTokenArray_T
{
    InputToken_T tokens[MAX_INPUT_TOKENS];
    int          count;
}InputTokenArray_T, *InputTokenArray;

static char cachedUsername[INPUT_STRING_LENGTH] = { 0 };
static char cachedPassword[INPUT_STRING_LENGTH] = { 0 };
static int  credentialCacheIsEmpty ();


static void  tokeniseString    (const char* inputString, InputTokenArray* outTokens);
static void  destroyTokenArray (InputTokenArray* tokenArray);

// input handler subroutines
static void  undefinedHandler  (const InputTokenArray tokens);
static void  refreshHandler    (const InputTokenArray tokens);
static void  MACHandler        (const InputTokenArray tokens);
static void  IPHandler         (const InputTokenArray tokens);
// Expects an IP address and lists all the machines
// on that switch
static void  switchListHandler (const InputTokenArray tokens);
// Lists all ports and their last input on a switch
static void  deadPortHandler   (const InputTokenArray tokens);
static void  helpHandler       (const InputTokenArray tokens);

static BOOL credentialCacheIsEmpty()
{
    return stringIsEmpty(cachedUsername) || stringIsEmpty(cachedPassword);
}

// I should have just called the functions directly but
// whatever I wanted to try a table like this
static inputHandlerFunction inputHandlers[INPUT_TYPE_COUNT] = 
{ 
                       // enum inputType index mapping:
	undefinedHandler,  // 0
	refreshHandler,    // 1 
	MACHandler,        // 2
	IPHandler,         // 3
	switchListHandler, // 4
    deadPortHandler,
    helpHandler
};

int handleInput(const char* userInputString)
{
    int             length      = getStrLen(userInputString);
    InputType       inType      = INPUT_TYPE_UNDEFINED;
    InputTokenArray inputTokens = NULL;

    tokeniseString        (userInputString, &inputTokens);
    if (inputTokens->count < 1) {
        return 1;
    }
    char* command = inputTokens->tokens[0].string;

    // TODO: maybe update this for the tokenisation
    // or at least make it a switch statement
    if (command[0] == 'r') {
        inType = INPUT_TYPE_REFRESH;
    } 
    else if (command[0] == 't') {
        inType = INPUT_TYPE_SWITCHLIST;
    }
    else if (command[0] == 'p') {
        inType = INPUT_TYPE_DEADPORT_LIST;
    }
    else if (command[0] == 'h') {
        inType = INPUT_TYPE_HELP;
    }
    else {
        for (int i = 0; i < length; i++) {
            // If a period is anywhere in the first token, it shall be an IP!
            if (findCHARSubstring(".", command, '\0') > 0) {
                inType = INPUT_TYPE_IP;
            }
        }
        // Default case, try to interpret it as MAC
        if (inType == INPUT_TYPE_UNDEFINED) {
            inType = INPUT_TYPE_MAC;
        }
    }
    inputHandlers[inType] (inputTokens);
    destroyTokenArray     (&inputTokens);

    return 0;
}

static void tokeniseString(const char* inputString, InputTokenArray *outTokens)
{
    int       *tokenCount   = NULL;
    int        stringIndex  = 0;
    int       *tokenLength  = NULL;
    InputToken currentToken = NULL;

    (*outTokens) = (InputTokenArray)calloc(1, sizeof(InputTokenArray_T));
    if ((*outTokens) == NULL) {
        exit(1);
    }

    tokenCount = &(*outTokens)->count;
    // TODO: this all sucks a bit
    while (*tokenCount < MAX_INPUT_TOKENS) {
        currentToken = &(*outTokens)->tokens[*tokenCount];
        tokenLength  = &currentToken->length;
        *tokenLength = goToNextChar(&inputString[stringIndex], ' ', 0);
        // TODO: capping token length looks messy here?
        if (*tokenLength > 0) {
            if (*tokenLength >= INPUT_TOKEN_LENGTH) {
                *tokenLength = INPUT_TOKEN_LENGTH - 1;
                currentToken->string[*tokenLength] = '\0';
            }
            memcpy(&currentToken->string, &inputString[stringIndex], (*tokenLength));
            (*tokenCount)++;
            stringIndex += (*tokenLength) + 1;
        }
        // We're encountering NUL character instead of ' ' character
        // so getStrLen instead for the last token.
        // This is wasteful and dumb, I should instead have a function
        // to count string length up to whitespace/NUL but whatever.
        else {
            *tokenLength = getStrLen(&inputString[stringIndex]);
            if (*tokenLength >= INPUT_TOKEN_LENGTH) {
                *tokenLength = INPUT_TOKEN_LENGTH - 1;
                currentToken->string[*tokenLength] = '\0';
            }
            memcpy(currentToken, &inputString[stringIndex], (*tokenLength));
            (*tokenCount)++;
            break;
        }
    }
}

static void destroyTokenArray(InputTokenArray* tokenArray)
{
    if ((*tokenArray) != NULL) {
        free(*tokenArray);
        *tokenArray = NULL;
    }
}

void getPassword(char* outString, const int maxLength) 
{
    int  i = 0;
    char ch;

    while (1){
        ch = _getch(); // Read a character without echoing
        if (ch == '\r' || ch == '\n') { // Check for Enter key
            outString[i] = '\0'; // Null terminate the password string
            break;
        }
        else if (ch == '\b' && i > 0) { // Handle backspace
            printf("\b \b"); // Erase the character from display
            i--;
        }
        else if (i < maxLength - 1 && ch != '\b') { // Store the character in the password if within limits
            outString[i] = ch;
            printf("*"); // Print '*' to show something's being typed
            i++;
        }
    }
}

void getInputString(char* outString, const int maxLength) 
{
    int  i  = 0;
    char ch = 0;

    while (1){
        ch = _getch(); // Read a character without echoing
        if (ch == '\r' || ch == '\n') { // Check for Enter key
            outString[i] = '\0';
            break;
        }
        else if (ch == '\b' && i > 0) { // Handle backspace
            printf("\b \b"); // Erase the character from display
            i--;
        }
        else if (i < maxLength - 1 && ch != '\b') { // Store the character in the string if within limits
            outString[i] = ch;
            printf("%c", ch);
            i++;
        }
    }
}


static void undefinedHandler(const InputTokenArray tokens)
{
    printf ("\nInput not valid.");
}

static void refreshHandler(const InputTokenArray tokens)
{
	printf         ("\nRefreshing DHCP data...");
	cleanupDHCP    ();
	initialiseDHCP ();
	printf         ("\nReady.");
	return;
}

static void MACHandler(InputTokenArray tokens)
{
    InputToken macToken                = &tokens->tokens[0];
    BYTE       mac[MAC_ADDRESS_LENGTH] = { 0 };

    getMACfromString       (macToken->string, mac, macToken->length);

    // TODO: this mac shit is slightly autistic. But only slightly
    const DWORD MAC_length = 
    getLengthFromInputMAC  (macToken->string, MAC_ADDRESS_LENGTH * 2);
    searchClientListForMAC (mac, MAC_length, &clients, &foundClients);
	tryPrintClientList     (&foundClients);
}

static void IPHandler(InputTokenArray tokens)
{
    InputToken ipToken = &tokens->tokens[0];
    DWORD      ip      = 0;
    DWORD      ipMask  = 0;

    getIPfromString       (ipToken->string, &ip, &ipMask, ipToken->length+1);
    searchClientListForIP (ip, ipMask, &clients, &foundClients);
	tryPrintClientList    (&foundClients);
}

static void switchListHandler(InputTokenArray tokens)
{
    const char *ipAddressString                        = tokens->tokens[1].string;
    // only used if there is a string search of a switch
    WCHAR        searchString   [INPUT_TOKEN_LENGTH]   = { 0 };

    ssh_session      SSHsession                             = ssh_new();
    DWORD            ip                                     = 0;
    DWORD            ipMask                                 = 0;
    SwitchPortArray  switchPortArray                        = NULL;
    SwitchPortArray  sortedSwitchPortArray                  = NULL;
    SwitchPortArray  searchedSwitchPortArray                = NULL;
    int              er                                     = 0;
    char            *sshOutputString                        = 
                (char*)calloc(SSH_BUFFER_SIZE, sizeof(char));

    if (sshOutputString == NULL){
        fprintf    (stderr, "\nBad malloc");
        return;
    }
    if (SSHsession == NULL) {
        fprintf(stderr, "\nCreating SSH session failed.");
        goto cleanup_output_string;
    }

    if (credentialCacheIsEmpty()) {
        printf         ("\nSSH username:");
        getInputString (cachedUsername, INPUT_STRING_LENGTH);
        printf         ("\nSSH password:");
        getPassword    (cachedPassword, INPUT_STRING_LENGTH);
    }
    // TODO: do error stuff proper maybe
    er =
	sshConnectAuth         (ipAddressString, cachedUsername, cachedPassword, SSHsession);
    if (er != SSH_OK){
        fprintf(stderr, "\nError connecting to ssh.\n");
        goto cleanup_output_string;
    }
    er =
    sshSingleRemoteExecute (SSHsession, 
                            "show mac address-table | e /49", 
                            sshOutputString);
    if (er != SSH_OK) {
        fprintf(stderr, "\nSSH remote execution error: %d", er);
        goto cleanup_ssh;
    }
    // TODO: check all allocations
    printf("%s", sshOutputString);
    er =
    extractSwitchPortData  (sshOutputString, 
                            SSH_BUFFER_SIZE, 
                            &switchPortArray);
    if (er != 0) {
        goto cleanup_ssh;
    }
    er =
    sortSwitchArray         (switchPortArray,
                             &sortedSwitchPortArray);
    if (er != 0) {
        fprintf(stderr, "\nError sorting switch list");
        goto cleanup_SPBuffer;
    }
    // search for smthn if there is a search string
    if (tokens->count > 2) {
        widenChars            (tokens->tokens[2].string, searchString, (DWORD)tokens->tokens[2].length);
        searchSwitchPortArray (tokens->tokens[2].string, (DWORD)tokens->tokens[2].length, sortedSwitchPortArray, &searchedSwitchPortArray);
        printSwitchPortArray  (searchedSwitchPortArray);
    }
    else {
        printSwitchPortArray  (sortedSwitchPortArray);
    }
    // TODO: cleanup all of the things here
    deleteSwitchPortArray  (&sortedSwitchPortArray);
    deleteSwitchPortArray  (&searchedSwitchPortArray);
cleanup_SPBuffer:
    deleteSwitchPortArray  (&switchPortArray);
cleanup_ssh:
    cleanupSSH             (SSHsession);
cleanup_output_string:
    free                   (sshOutputString);
    return;
}

static void deadPortHandler(InputTokenArray tokens)
{
    const char *ipAddressString                      = tokens->tokens[1].string;
    DWORD       ip                                   = 0;
    DWORD       ipMask                               = 0;
    SwitchPort  switchPortBuffer                     = NULL;
    int         er                                   = 0;
    
    char*       sshOutputString  = (char*)calloc(SSH_BUFFER_SIZE, sizeof(char));
    ssh_session SSHsession       = ssh_new();

    if (sshOutputString == NULL) {
        fprintf    (stderr, "\nBad malloc");
        if (SSHsession != NULL) {
            cleanupSSH(SSHsession);
        }
        return;
    }
    if (SSHsession == NULL) {
        fprintf(stderr, "\nFailed to create SSH session.");
        free(sshOutputString);
        return;
    }
    if (!credentialCacheIsEmpty()) {
        printf         ("\nSSH username:");
        getInputString (cachedUsername, INPUT_STRING_LENGTH);
        printf         ("\nSSH password:");
        getPassword    (cachedPassword, INPUT_STRING_LENGTH);
    }
    // TODO: do error stuff proper maybe
    er =
	sshConnectAuth         (ipAddressString, cachedUsername, cachedPassword, SSHsession);
    if (er != 0) {
        fprintf(stderr, "\nError connecting to ssh.\n");
		free(sshOutputString);
		return;
    }
    er =
    sshSingleRemoteExecute (SSHsession,
                            "sh int | i proto.*notconnect| Last input",
                            sshOutputString);
    if (er != SSH_OK) {
        fprintf(stderr, "\nSSH remote execution error: %d", er);
		free(sshOutputString);
		return;
    }
    printf                 ("\n%s\n", sshOutputString);
cleanup:
    free                   (sshOutputString);
    cleanupSSH             (SSHsession);
    return;
}
static void helpHandler(InputTokenArray tokens)
{
    printf("\n-------------------");
    printf("\n       Help");
    printf("\n-------------------");
    printf("\nSearch for MAC:");
    printf("\n- Enter a MAC address or partial MAC address in lower case characters");
	printf("\n  with no delimiters to search for a MAC, e.g.: \"00e0\"\n");
    printf("\nSearch for IP:");
    printf("\n- Enter an IP address in decimal format to search for an IP e.g.: \"10.10.2.44\"\n");
    printf("\nList All Clients in a Subnet:");
    printf("\n- Enter a partial IP address to list every client in a subnet e.g.: \"10.10.255\"\n");
    printf("\nList All Clients on a Switch:");
    printf("\n- Enter \"t IP_ADDRESS\" to list all devices on a Cisco IOS switch at that IP address.\n");
    printf("\nList Unused Ports on a Switch:");
    printf("\n- Enter \"n IP_ADDRESS\" to list the last input on");
	printf("\n  each port for a Cisco IOS switch at the given IP address.\n");
    printf("\nResync DHCP data with servers:");
    printf("\n- Enter \"r\" to refresh data.");
    printf("\n--------------------\n");
}
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
