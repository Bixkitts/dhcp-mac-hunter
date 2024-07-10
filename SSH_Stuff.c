#include "SSH_Stuff.h"

struct SwitchPort_T
{
	char             portString  [MAX_LABEL_STRING_LENGTH];
    // Each list will typically represent a search for a MAC,
    // and contain one client (potentially multiple results tho)
    // TODO: Perhaps this is too much indirection and
    // I should concatenate lists?
	DHCPClientList_T clientlists [MAX_CLIENT_LISTS_PER_PORT];
	int              clientListCount;
};

struct SwitchPortArray_T
{
    SwitchPort_T ports     [MAX_PORTS_IN_STACK];
    char        *switchName[MAX_LABEL_STRING_LENGTH];
    int          portCount;
};

typedef enum {
	PORT_TYPE_TE,
	PORT_TYPE_GI,
	PORT_TYPE_FA,
	PORT_TYPE_COUNT
}PortType;

static int  verify_knownhost          (ssh_session session);
// TODO: this assumes max size and does not dynamically scale
static int  allocateSwitchPortArray   (SwitchPortArray* outArray);
static void copySwitchPort            (const SwitchPort inPort, 
                                       SwitchPort outPort);

static int verify_knownhost(ssh_session session)
{
    // TODO: uninitialised
    enum ssh_known_hosts_e  state;
    unsigned char          *hash       = NULL;
    ssh_key                 srv_pubkey = NULL;
    size_t                  hlen;
    char                    buf[10];
    char                   *hexa;
    char                   *p;
    int                     rc;
 
    rc = 
    ssh_get_server_publickey (session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    // TODO: set the hash up properly
    rc = 
    ssh_get_publickey_hash   (srv_pubkey,
                              SSH_PUBLICKEY_HASH_SHA1,
                              &hash,
                              &hlen);
    ssh_key_free             (srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */
 
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf               (stderr, "\nHost key for server changed: it is now:\n");
            ssh_print_hexa        ("Public key hash", hash, hlen);
            fprintf               (stderr, "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash (&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf               (stderr, "\nThe host key for this server was not found but an other"
                                   "type of key exists.\n");
            fprintf               (stderr, "An attacker might change the default server key to"
                                   "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash (&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr, "\nCould not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
 
            /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
 
        case SSH_KNOWN_HOSTS_UNKNOWN:
            hexa = 
            ssh_get_hexa          (hash, hlen);

            fprintf               (stderr,
                                   "\nThe server is unknown. Do you trust the host key?\n");
            fprintf               (stderr, 
                                   "Public key hash: %s\n", hexa);
            ssh_string_free_char  (hexa);
            ssh_clean_pubkey_hash (&hash);

            p = 
            fgets                 (buf, sizeof(buf), stdin);
            if (p == NULL) {
                return -1;
            }
 
            if (buf[0] != 'y') {
                return -1;
            }
 
            rc = 
            ssh_session_update_known_hosts (session);
            if (rc < 0) {
                fprintf(stderr, "Error with known hosts!!!!\n");
                return -1;
            }
 
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            fprintf               (stderr, "\nError %s", ssh_get_error(session));
            ssh_clean_pubkey_hash (&hash);
            return -1;
    }
 
    ssh_clean_pubkey_hash(&hash);
    return 0;
}
// All the parameter strings need to be null terminated!!
int sshConnectAuth(const char* address, const char* username, const char* password, ssh_session outSession)
{
    int rc;

    if (outSession == NULL)
        return -1;
    ssh_options_set(outSession, SSH_OPTIONS_HOST, address);
    ssh_options_set(outSession, SSH_OPTIONS_KEY_EXCHANGE, "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1");
    ssh_options_set(outSession, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
    ssh_options_set(outSession, SSH_OPTIONS_HMAC_C_S, "hmac-sha1,hmac-sha1-96");
    ssh_options_set(outSession, SSH_OPTIONS_HMAC_S_C, "hmac-sha1,hmac-sha1-96");
    ssh_options_set(outSession, SSH_OPTIONS_CIPHERS_C_S, "aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc,aes128-gcm,aes256-gcm,aes128-ctr,aes192-ctr,aes256-ctr");
    ssh_options_set(outSession, SSH_OPTIONS_CIPHERS_S_C, "aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc,aes128-gcm,aes256-gcm,aes128-ctr,aes192-ctr,aes256-ctr");
    rc = 
    ssh_connect(outSession);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "\nError connecting to server: %s\n",
                ssh_get_error(outSession));
        ssh_free(outSession);
        outSession = NULL;
        return -1;
    }
    
    if (verify_knownhost(outSession) < 0)
    {
        ssh_disconnect (outSession);
        ssh_free       (outSession);
        outSession = NULL;
        return -1;
    }
    rc = 
    ssh_userauth_password(outSession, username, password);
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf        (stderr, 
                        "\nError authenticating with password: %s\n",
                        ssh_get_error(outSession));
        ssh_disconnect (outSession);
        ssh_free       (outSession);
        outSession = NULL;
    }
    return rc;
}

int sshSingleRemoteExecute(ssh_session session, const char* command, char* outString)
{
    if (outString == NULL) {
        fprintf(stderr, "\nCan't write SSH output to NULL string");
        return -1;
    }
    ssh_channel channel;
    int         rc;
    char        buffer[256];
    int         nbytes;
    size_t      total_read = 0;
    const char *error;

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        error = ssh_get_error(session);
        if (error != NULL) {
            printf("\nError creating channel: %s\n", error);
            ssh_string_free_char(error);
        }
        return SSH_ERROR;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    memset(outString, 0, SSH_BUFFER_SIZE); // Clear the output buffer

    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
        if (total_read + nbytes < SSH_BUFFER_SIZE) {
            memcpy(outString + total_read, buffer, nbytes);
            total_read += nbytes;
        }
        else {
            fprintf(stderr, "\nOutput buffer filled....");
            // Output buffer full, handle error or resize buffer as needed
            break;
        }
    }

    outString[SSH_BUFFER_SIZE - 1] = '\0';
    ssh_channel_send_eof (channel);
    ssh_channel_close    (channel);
    ssh_channel_free     (channel);

    if (nbytes < 0) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

void cleanupSSH(ssh_session session)
{
    if (session == NULL) {
        return;
    }
    ssh_disconnect (session);
    ssh_free       (session);
}

// Converts XXXX.XXXX.XXXX MAC format to XXXXXXXXXXXX
static int convertDotMacStringMac(const char* dotMAC, char *stringMAC)
{
	int       index           = 0;
	const int macStringLength = 12;

	index = goToNextChar(dotMAC, '.', index);
	if (index < 0) {
		return -1;
	}
	index -= 4;
	int i  = 0;
	while (i < macStringLength){
		if (dotMAC[index] != '.') {
			stringMAC[i] = dotMAC[index];
			i++;
		}
		index++;
	}
    return 0;
}

void printSwitchPortArray(const SwitchPortArray portArray)
{
    // The presence of a portString dictates whether we're done printing the buffer
    for (int index = 0; index < portArray->portCount; index++) {
        printf("\n\n");
        printSwitchName(portArray);
        printf(" Port %s:", portArray->ports[index].portString);
        printf("\n--------------------");
        for (int j = 0; j < portArray->ports[index].clientListCount; j++) {
            tryPrintClientList(&portArray->ports[index].clientlists[j]);
        }
    }

}

static int getPortStringOnLine(const char* const inBuffer, char* outPortString)
{
    int offset = 0;
	offset = findCHARSubstring("Gi", inBuffer, '\n');
	if (offset >= 0) {
        goto successful_conclusion;
	}
	offset = findCHARSubstring("Fa", inBuffer, '\n');
	if (offset >= 0) {
        goto successful_conclusion;
	}
	offset = findCHARSubstring("Te", inBuffer, '\n');
	if (offset >= 0) {
        goto successful_conclusion;
	}
    else {
        return -1;
    }

successful_conclusion:
	memcpy         (outPortString, &inBuffer[offset], 30);
	truncateString (outPortString, 32);
    return offset;
}

// TODO: currently we always allocate at max possible volume because it's not that
// much, but I may want to dynamically scale these arrays.
static int allocateSwitchPortArray(SwitchPortArray* outArray)
{
	deleteSwitchPortArray(outArray);
    (*outArray) = (SwitchPortArray)calloc(1, sizeof(SwitchPortArray_T));
    if ((*outArray) == NULL) {
        fprintf(stderr, "\nSwitchPort Array MALLOC ERROR");
        exit(1);
        return -1;
    }
    return 0;
}

void deleteSwitchPortArray(SwitchPortArray* array)
{
    if (*array == NULL) {
        return;
    }
    for (int i = 0; i < (*array)->portCount; i++) {
        // Each port in the port array will have multiple
        // client lists in it, one for each search performed.
        // TODO: maybe make it one concatenated client list
        // per port?
        for (int j = 0; j < (*array)->ports[i].clientListCount; j++) {
            clearDHCPClientList(&(*array)->ports[i].clientlists[j]);
        }
    }
    free(*array);
    *array = NULL;
    return;
}

int extractSwitchPortData(const char* inBuffer, DWORD inBufferSize, SwitchPortArray* outBuffer)
{
    int         *portCount       = NULL;
    int          portIndex       = 0;
    long int     inBufferIndex   = 0;
    int          offset          = 0;
    SwitchPort   portArray       = NULL;
	char         portString[MAX_LABEL_STRING_LENGTH]    = { 0 };
	char         macBuffer [MAX_ADDRESS_STRING_LENGTH]  = { 0 };


    allocateSwitchPortArray(outBuffer);
    portArray = (*outBuffer)->ports;
    portCount = &(*outBuffer)->portCount;

    // Bring us to the first line that'll have a MAC address on it,
    // which on Cisco IOS switch is incidentally the first line
    // that says "STATIC"... as far as I can tell.
    inBufferIndex = findCHARSubstring ("STATIC", inBuffer, 0);
    inBufferIndex = goToStartOfLine   (inBuffer, inBufferIndex);

    while (inBufferIndex < inBufferSize){
        memset                 (portString, 0, sizeof(portString));
        memset                 (macBuffer, 0, sizeof(macBuffer));
        convertDotMacStringMac (&inBuffer[inBufferIndex], macBuffer);
        
        // Get the name of the port on the SSH line
		inBufferIndex = 
        goToStartOfLine        (inBuffer, inBufferIndex);
        offset =
        getPortStringOnLine    (&inBuffer[inBufferIndex], portString);
        if (offset < 0){
            goto next_line;
        }
        inBufferIndex += offset;
        // We're not interested in uplink interfaces.
        // This is also a dirty hack that should work on the older port string format
        // i.e.: GiX/X vs GiX/X/X
        // TODO: pray that there are never more than 9 switches in a stack
        if (inBuffer[inBufferIndex + 4] == '1' && inBuffer[inBufferIndex + 5] == '/') {
            goto next_line;
        }
        // Compare the port strings from the SSH output
        for (int i = 0; i < MAX_PORTS_IN_STACK; i++)
        { 
            // TODO: potential overflow?
            if (strcmp(portArray[i].portString, portString) == 0) {
                portIndex = i;
                break;
            }
            else if (i >= (*portCount)) {
                memcpy(portArray[i].portString, portString, sizeof(portArray[i].portString));
                portIndex = (*portCount);
                (*portCount)++;
                break;
            }
        }
        // -----------------------------
        // Here we build a client list in place of a NULL pointer,
        // from a search for the MAC address interpreted from the
        // SSH console output
        SwitchPort currentPort     = &portArray[portIndex];
        int       *clientListCount = &currentPort->clientListCount;
        BYTE       MAC[6]          = { 0 };
        truncateString               (macBuffer, MAX_ADDRESS_STRING_LENGTH);
        getMACfromString             (macBuffer,MAC, MAX_ADDRESS_STRING_LENGTH);
		searchClientListForMAC       (MAC, 
                                      MAC_ADDRESS_LENGTH, 
                                      &clients, 
                                      &currentPort->clientlists[(*clientListCount)]);
        // bounds check
        if (*clientListCount < MAX_CLIENT_LISTS_PER_PORT) {
            (*clientListCount)++;
        }
        else {
            break;
        }
	next_line:
        inBufferIndex = goToStartOfNextLine(inBuffer, inBufferIndex);
        if ( inBufferIndex < 0) {
            break;
        }
    }
    return 0;
}

int searchSwitchPortArray(const WCHAR* string, const DWORD strlen, const SwitchPortArray inPortArray, SwitchPortArray* outPortArray)
{
    int         inPortIndex    = 0;
    int*        outPortCount   = NULL;

    char* currentPortString = NULL;
    SwitchPort* tempArray   = NULL;

    allocateSwitchPortArray(outPortArray);
    outPortCount = &(*outPortArray)->portCount;
    *outPortCount = 0;

    setSwitchName((*outPortArray), getSwitchName(inPortArray));

    // first pass - store pointers in sequential array
    while (inPortIndex < inPortArray->portCount) {

        for (int i = 0; i < inPortArray->ports[inPortIndex].clientListCount; i++) {
            if (searchClientListForString(string, &inPortArray->ports[inPortIndex].clientlists[i]) > -1) {
                copySwitchPort(&inPortArray->ports[inPortIndex], &(*outPortArray)->ports[*outPortCount]);
                if (*outPortCount < MAX_PORTS_IN_STACK) {
                    (*outPortCount)++;
                }
                else {
                    fprintf(stderr, "\nSearching failed: buffer overflow");
                    return -1;
                }

                break;
            }              
        }
        inPortIndex++;
    }
    return 0;
}

static void copySwitchPort(const SwitchPort inPort, SwitchPort outPort)
{
    if (inPort == NULL) {
        return;
    }
    for (int i = 0; i < inPort->clientListCount; i++) {
        copyDHCPClientList(&inPort->clientlists[i], &outPort->clientlists[i]);
    }
    outPort->clientListCount = inPort->clientListCount;
    memcpy(outPort->portString, inPort->portString, sizeof(outPort->portString));
}

int sortSwitchArray(const SwitchPortArray inPortArray, SwitchPortArray* outPortArray)
{
    int         inPortIndex       = 0;
    int        *outPortCount      = NULL;
    // Indeces into the port string denoting where to find data
    int         portNumIndex;
    const int   switchNumIndex    = 2; // this seems to be the same on any Cisco switch
    // -------The integers interpreted from the string data-----//
    PortType    portType          = 0;                         //
	int         switchNum         = 0;                        //
	int         portNum           = 0;                       //
    // -------------------------------------------------------
    int         intAsciiOffset;
    int         switchIndexer     = 0;
    char       *currentPortString = NULL;
    SwitchPort *tempArray         = NULL;

    enum portIndeces{
        OLD_SWITCH_PORT_INDEX = 4,
        NEW_SWITCH_PORT_INDEX = 6
    };

    // Older switches only have two digits in the port string instead of three
    // e.g.: Gi0/1 instead of Gi1/0/1
    // ASCII offset is changed because old switches start at index 0 while
    // new ones start at 1.
    if (inPortArray->ports[0].portString[5] != '/') {
        portNumIndex   = OLD_SWITCH_PORT_INDEX;
        intAsciiOffset = 47;
    }
    else {
        portNumIndex   = NEW_SWITCH_PORT_INDEX;
        intAsciiOffset = 48;
    }

    allocateSwitchPortArray(outPortArray);
    outPortCount = &(*outPortArray)->portCount;
    *outPortCount = 0;

    setSwitchName((*outPortArray), getSwitchName(inPortArray));

    tempArray = (SwitchPort*)calloc(MAX_PORTS_IN_STACK * PORT_TYPE_COUNT, sizeof(SwitchPort));
    if (tempArray == NULL) {
        deleteSwitchPortArray(outPortArray);
        return -1;
    }
    // first pass - store pointers in sequential array
    while(inPortIndex < inPortArray->portCount){
        currentPortString = inPortArray->ports[inPortIndex].portString;
        switch(currentPortString[0]){
        case 'T': 
            portType = PORT_TYPE_TE;
            break;
        case 'G':
            portType = PORT_TYPE_GI;
            break;
        case 'F':
            portType = PORT_TYPE_FA;
            break;
        default:
            portType = PORT_TYPE_FA;
            break;
        }
        switchNum         = (int)((currentPortString[switchNumIndex]) - intAsciiOffset);
        portNum           = atoi(&currentPortString[portNumIndex]);

        tempArray[(portType+1) * ((switchNum * MAX_PORTS_ON_SWITCH) + portNum)] = &inPortArray->ports[inPortIndex];
        inPortIndex++;
    }
    // second pass - Put all non-null array addresses next to eachother.
    for (portNum = 0; portNum < MAX_PORTS_IN_STACK * PORT_TYPE_COUNT; portNum++) {
		if (tempArray[portNum] != NULL) {
            copySwitchPort(tempArray[portNum], &(*outPortArray)->ports[*outPortCount]);
			if (*outPortCount < MAX_PORTS_IN_STACK) {
				(*outPortCount)++;
			}
			else {
				fprintf (stderr, "\nSorting failed: buffer overflow");
				free    (tempArray);
				return -1;
			}
		}
    }
    free(tempArray);
    return 0;
}
char* getSwitchName(SwitchPortArray_T* array)
{
    return array->switchName;
}
void setSwitchName(SwitchPortArray_T* array, const char* string) 
{
    strncpy_s(array->switchName, MAX_LABEL_STRING_LENGTH, string, MAX_LABEL_STRING_LENGTH - 1);
}
void printSwitchName(SwitchPortArray_T* array)
{
    printf("%s", array->switchName);
}

//	Copyright(C) 2023 Sean Bix, full license in MAC_Hunt3r2.c
