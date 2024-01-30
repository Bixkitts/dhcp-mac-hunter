#include "InputHandling.h"

static char username[INPUT_STRING_LENGTH] = { 0 };
static char password[INPUT_STRING_LENGTH] = { 0 };

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
    helpHandler,
    passwordReset
};

DWORD handleInput(char* input, char* output, DWORD length)
{
    inputType inType = INPUT_TYPE_UNDEFINED;
	printf("\n-----------------------------------------");
    printf("\nEnter \"h\" for help, or enter a command>");

	if (fgets(input, length, stdin) == NULL) {
		printf("Error reading input.\n");
		return 1;
	}
    input[length - 1] = 0;
    if (input[0] == 'r'){
        inType = INPUT_TYPE_REFRESH;
    } 
    else if (input[0] == 't'){
        inType = INPUT_TYPE_SWITCHLIST;
    }
    else if (input[0] == 'n') {
        inType = INPUT_TYPE_DEADPORT_LIST;
    }
    else if (input[0] == 'p') {
        inType = INPUT_TYPE_PWRESET;
    }
    else if (input[0] == 'h') {
        inType = INPUT_TYPE_HELP;
    }
    else {
        for (int i = 0; i < length; i++) {
            if (input[i] == '.') {
                inType = INPUT_TYPE_IP;
            }
        }
        // Default case, try to interpret it as MAC
        if (inType == INPUT_TYPE_UNDEFINED) {
            inType = INPUT_TYPE_MAC;
        }
    }
    inputHandlers[inType](input, output, length);
    return ERROR_SUCCESS;
}

void undefinedHandler(const char* input, char* output, DWORD length)
{
    printf ("\nInput not valid.");
}

void refreshHandler(const char* input, char* output, DWORD length)
{
	printf         ("\nRefreshing DHCP data...");
	cleanupDHCP    ();
	initialiseDHCP ();
	printf         ("\nReady.");
	return;
}

void passwordReset(const char* input, char* output, DWORD length)
{
    memset(password, 0, INPUT_STRING_LENGTH);
    memset(username, 0, INPUT_STRING_LENGTH);
    printf("\nUsername and password credentials cleared.");
}

void MACHandler(const char* input, char* output, DWORD length)
{
    // Default case if the other checks fail, it looks up a MAC
    getMACfromString       (input, output, length);

    const DWORD MAC_length = 
    getLengthFromInputMAC  (input, MAC_ADDRESS_LENGTH * 2);
    searchClientListForMAC (output, MAC_length, &clients, &foundClients);
	printClients           (foundClients);
}

void IPHandler(const char* input, char* output, DWORD length)
{
    DWORD ip = 0;
    DWORD ipMask = 0;
    getIPfromString       (input, &ip, &ipMask, length);
    searchClientListForIP (ip, ipMask, &clients, &foundClients);
	printClients          (foundClients);
}

void switchListHandler(const char* input, char* output, DWORD length)
{
    const int   ipOffset                             = 3; /* Which character the ip address starts at */
    char        ipAddressString[INPUT_STRING_LENGTH] = { 0 };
    ssh_session SSHsession                           = ssh_new();
    DWORD       ip                                   = 0;
    DWORD       ipMask                               = 0;
    SwitchPort  switchPortBuffer                     = NULL;
    SwitchPort  sortedSwitchPortBuffer               = NULL;
    int         er                                   = 0;
    char       *sshOutputString                      = 
                (char*)calloc(SSH_BUFFER_SIZE, sizeof(char));

    if (sshOutputString == NULL){
        fprintf    (stderr, "\nBad malloc");
        return;
    }
    if (SSHsession == NULL) {
        fprintf(stderr, "\nCreating SSH session failed.");
        goto cleanup_output_string;
    }
    memcpy                 (ipAddressString, 
                            &input[ipOffset-1], 
                            INPUT_STRING_LENGTH-ipOffset);
    if (password[0] == '\0') {
        printf         ("\nSSH username:");
        if (fgets(username, length, stdin)
        == NULL){
            printf ("Error reading input.\n");
            return;
        }
        username[length - 1] = 0;

        printf         ("\nSSH password:");
        getPassword    (password, INPUT_STRING_LENGTH);

        truncateString (username, INPUT_STRING_LENGTH);
    }
	truncateString         (&ipAddressString[ipOffset], 
                            INPUT_STRING_LENGTH - ipOffset);
    // TODO: do error stuff proper maybe
    er =
	sshConnectAuth(ipAddressString, username, password, SSHsession);
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
    er =
    extractSwitchPortData  (sshOutputString, 
                            SSH_BUFFER_SIZE, 
                            &switchPortBuffer);
    if (er != 0) {
        goto cleanup_ssh;
    }
    er =
    sortSwitchList         (switchPortBuffer,
                            &sortedSwitchPortBuffer);
    if (er != 0) {
        fprintf(stderr, "\nError sorting switch list");
        goto cleanup_SPBuffer;
    }
    printSwitchPortBuffer  (sortedSwitchPortBuffer);

    for (int i = 0; i < MAX_PORTS_IN_STACK; i++) {
        for (int j = 0; j < switchPortBuffer[i].clientCount; j++) {
			freeShallowDstClientList(&switchPortBuffer[i].clients[j]);
        }
    }
    free                   (sortedSwitchPortBuffer);
cleanup_SPBuffer:
    free                   (switchPortBuffer);
cleanup_ssh:
    cleanupSSH             (SSHsession);
cleanup_output_string:
    free                   (sshOutputString);
    return;
}

void deadPortHandler(const char* input, char* output, DWORD length)
{
    const int   ipOffset                             = 3; /* Which character the ip address starts at */
    char        ipAddressString[INPUT_STRING_LENGTH] = { 0 };
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

    memcpy(ipAddressString,
           &input[ipOffset - 1],
           INPUT_STRING_LENGTH - ipOffset);
    if (password[0] == '\0') {
        printf         ("\nSSH username:");
        if (fgets(username, length, stdin)
            == NULL) {
            printf("Error reading input.\n");
            return;
        }
        username[length - 1] = 0;

        printf         ("\nSSH password:");
        getPassword    (password, INPUT_STRING_LENGTH);

        truncateString (username, INPUT_STRING_LENGTH);
    }
    truncateString(&ipAddressString[ipOffset],
                   INPUT_STRING_LENGTH - ipOffset);
    // TODO: do error stuff proper maybe
    er =
	sshConnectAuth         (ipAddressString, username, password, SSHsession);
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
void  helpHandler(const char* input, char* output, DWORD length)
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
    printf("\n- Enter \"r\" to refresh DHCP data");
    printf("\n This will redownload data from DHCP servers in servers.conf");
    printf("\n- Enter \"p\" to reset credentials");
    printf("\nYour credentials will be cleared from cache. \nNOTE: They are not encrypted while in memory.\nNOTE: The credentials should authenticate you for both SSH and DHCP.");
    printf("\n--------------------\n");
}
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
