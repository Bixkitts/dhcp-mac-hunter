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
	switchListHandler  // 4
};

DWORD handleInput(char* input, char* output, DWORD length)
{
    printf("\n\nEnter a MAC address, partial MAC, IP address, OR \"r\" to refresh DHCP data.");
    printf("\nType \"t IP_ADDRESS\" to search a switch:");

	if (fgets(input, length, stdin) == NULL) {
		printf("Error reading input.\n");
		return 1;
	}
    input[length - 1] = 0;
    inputType inType = INPUT_TYPE_UNDEFINED;
    if (input[0] == 'r'){
        inType = INPUT_TYPE_REFRESH;
    }
    for (int i = 0; i < length; i++){
        if (input[i] == '.'){
            inType = INPUT_TYPE_IP;
        }
    }

    if (input[0] == 't'){
        inType = INPUT_TYPE_SWITCHLIST;
    }
    // Default case
    if (inType == INPUT_TYPE_UNDEFINED){
        inType = INPUT_TYPE_MAC;
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
    switchPort  switchPortBuffer                     = NULL;
    
    memcpy                 (ipAddressString, 
                            &input[ipOffset-1], 
                            INPUT_STRING_LENGTH-ipOffset);
    if (password[0] == '\0') {
        printf         ("\nSSH username:");
        if (fgets  (username, length, stdin)
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
    if (sshConnectAuth(ipAddressString, username, password, SSHsession) 
    != 0){
        fprintf(stderr, "\nError connecting to ssh.\n");
        return;
    }
    char *sshOutputString = (char*)calloc(SSH_BUFFER_SIZE, sizeof(char));
    if (sshOutputString == NULL){
        fprintf    (stderr, "\nBad malloc");
        cleanupSSH (SSHsession);
        return;
    }
    sshSingleRemoteExecute (SSHsession, 
                            "show mac address-table | e /49", 
                            sshOutputString);
    extractSwitchPortData  (sshOutputString, 
                            SSH_BUFFER_SIZE, 
                            &switchPortBuffer);
    printSwitchPortBuffer  (switchPortBuffer);

    for (int i = 0; i < 512; i++) {
        for (int j = 0; j < switchPortBuffer[i].clientCount; j++) {
			freeShallowDstClientList(&switchPortBuffer[i].clients[j]);
        }
    }
    free                   (switchPortBuffer);
    cleanupSSH             (SSHsession);
    return;
}

//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
