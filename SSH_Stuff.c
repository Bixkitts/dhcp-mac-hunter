#include "SSH_Stuff.h"

static int verify_knownhost(ssh_session session)
{
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
void printSwitchPortBuffer(const SwitchPort buffer)
{
    int index = 0;
    // The presence of a portString dictates whether we're done printing the buffer
    while (buffer[index].portString[0] != 0){
        printf("\n\nSwitch Port %s:", buffer[index].portString);
        printf("\n--------------------");
        for (int j = 0; j < buffer[index].clientCount; j++) {
            if (buffer[index].clients[j].data[0]->NumElements == 0) {
                BYTE* errMAC = buffer[index].clients[j].errorMAC;
				wprintf(L"\nNo results for mac: %02x:%02x:%02x:%02x:%02x:%02x",
					   errMAC[0],
					   errMAC[1],
					   errMAC[2],
					   errMAC[3],
					   errMAC[4],
					   errMAC[5]);

            }
            else {
                printClients(buffer[index].clients[j]);
            }
        }
        index++;
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

int extractSwitchPortData(const char* inBuffer, DWORD inBufferSize, SwitchPort* outBuffer)
{
    int          portCount       = 0;
    int          portIndex       = 0;
    long int     index           = 0;
    int          offset          = 0;
	char         portString[32]  = { 0 };
	char         macBuffer [16]  = { 0 };

    *outBuffer = (SwitchPort)calloc(MAX_PORTS_IN_STACK, sizeof(SwitchPort_T));
    if (*outBuffer == NULL) {
        return -1;
    }

    while (index < inBufferSize){
        memset(portString, 0, 32);
        memset(macBuffer, 0, 16);
        convertDotMacStringMac (&inBuffer[index], macBuffer);
        
        // Get the name of the port on the SSH line
		index = 
        goToStartOfLine        (inBuffer, index);
        offset =
        getPortStringOnLine    (&inBuffer[index], portString);
        if (offset < 0){
            goto next_line;
        }
        index += offset;
        // We're not interested in uplink interfaces.
        // This is also a dirty hack that should work on the older port string format
        // i.e.: GiX/X vs GiX/X/X
        // TODO: pray that there are never more than 9 switches in a stack
        if (inBuffer[index + 4] == '1' && inBuffer[index + 5] == '/') {
            goto next_line;
        }
        // Compare the port strings from the SSH output
        for (int i = 0; i < MAX_PORTS_IN_STACK; i++)
        { 
            // TODO: overflow
            if (strcmp((*outBuffer)[i].portString, portString) == 0) {
                portIndex = i;
                break;
            }
            else if (i >= portCount) {
                memcpy((*outBuffer)[i].portString, portString, 32);
                portIndex = portCount;
                portCount++;
                break;
            }
        }
        // -----------------------------
        SwitchPort currentPort = &(*outBuffer)[portIndex];
        int        clientCount = currentPort->clientCount;
        BYTE       MAC[6]      = { 0 };
        truncateString               (macBuffer, 16);
        getMACfromString             (macBuffer,MAC, 16);
        allocateShallowDstClientList (&currentPort->clients[clientCount]);
		searchClientListForMAC       (MAC, 
                                      MAC_ADDRESS_LENGTH, 
                                      &clients, 
                                      &currentPort->clients[clientCount]);
        // bounds check
        if ((*outBuffer)[portIndex].clientCount < 255) {
            (*outBuffer)[portIndex].clientCount++;
        }
        else {
            break;
        }
	next_line:
        index = goToStartOfNextLine(inBuffer, index);
        if ( index < 0) {
            break;
        }
    }
    return 0;
}

int sortSwitchList(const SwitchPort inList, SwitchPort* outList)
{
    int         inListIndex       = 0;
    int         outListIndex      = 0;
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

    static enum portIndeces{
        OLD_SWITCH_PORT_INDEX = 4,
        NEW_SWITCH_PORT_INDEX = 6
    };

    // Older switches only have two digits in the port string instead of three
    // e.g.: Gi0/1 instead of Gi1/0/1
    // ASCII offset is changed because old switches start at index 0 while
    // new ones start at 1.
    if (inList[0].portString[5] != '/') {
        portNumIndex   = OLD_SWITCH_PORT_INDEX;
        intAsciiOffset = 47;
    }
    else {
        portNumIndex   = NEW_SWITCH_PORT_INDEX;
        intAsciiOffset = 48;
    }

    *outList  = (SwitchPort)calloc(MAX_PORTS_IN_STACK, sizeof(SwitchPort_T));
    if ((*outList) == NULL) {
        return -1;
    }
    tempArray = (SwitchPort*)calloc(MAX_PORTS_IN_STACK * PORT_TYPE_COUNT, sizeof(SwitchPort));
    if (tempArray == NULL) {
        free(*outList);
        return -1;
    }
    // first pass - store pointers in sequential array
    while (inList[inListIndex].portString[0] != '\0') {
        currentPortString = inList[inListIndex].portString;
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

        tempArray[(portType+1)*switchNum*portNum] = &inList[inListIndex];
        inListIndex++;
    }
    // second pass - Put all non-null array addresses next to eachother.
    for (portNum = 0; portNum < MAX_PORTS_IN_STACK * PORT_TYPE_COUNT; portNum++) {
		if (tempArray[portNum] != NULL) {
			memcpy(&(*outList)[outListIndex], tempArray[portNum], sizeof(SwitchPort_T));
			if (outListIndex < MAX_PORTS_IN_STACK) {
				outListIndex++;
			}
			else {
				fprintf(stderr, "\nSorting failed: buffer overflow");
				free(tempArray);
				return -1;
			}
		}
    }
    free(tempArray);
    return 0;
}
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
