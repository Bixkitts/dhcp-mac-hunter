#include "DHCP_Stuff.h"
#include "Defines.h"

Serverlist     servers;
DHCPClientList clients;
DHCPClientList foundClients;

DWORD initialiseDHCP()
{
	readTxtList("./servers.conf", &servers);
	allocateShallowDstClientList(&foundClients);
	getAllClientsFromDHCPServers(&servers, &clients);
    return ERROR_SUCCESS;
}

void cleanupDHCP()
{
    servers.length = 0;
    free                     (servers.list);
	cleanupUserList          (&clients);
    freeShallowDstClientList (&foundClients);
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

void allocateShallowDstClientList(DHCPClientList *list)
{
    list->data = (LPDHCP_CLIENT_INFO_ARRAY_VQ*)calloc(1, sizeof(LPDHCP_CLIENT_INFO_ARRAY_VQ));
    if (list->data == NULL){
        perror("\nmalloc failure!!");
        exit(1);
    }
    list->data[0] = (LPDHCP_CLIENT_INFO_ARRAY_VQ)calloc(1, sizeof(DHCP_CLIENT_INFO_ARRAY_VQ));
    if (list->data[0] == NULL){
        perror("\nmalloc failure!!");
        exit(1);
    }
    list->count = 1;
    list->data[0]->NumElements = 0;
    list->data[0]->Clients = (LPDHCP_CLIENT_INFO_VQ*)calloc(CLIENTS_MAX, sizeof(LPDHCP_CLIENT_INFO_VQ));
    if (list->data[0]->Clients == NULL){
        perror("\nmalloc failure!!");
        exit(1);
    }
}

void freeShallowDstClientList(DHCPClientList* list)
{
    free(list->data[0]->Clients);
    free(list->data[0]);
    free(list->data);
}

void searchClientListForIP(const DWORD inIP, const DWORD ipMask, const DHCPClientList *clients_in, DHCPClientList *results)
{
    results->data[0]->NumElements = 0;
    results->count = 1;
    for (DWORD i = 0; i < clients_in->count; i++)
    {
        for (DWORD j = 0; j < clients_in->data[i]->NumElements; j++)
        {
            LPDHCP_CLIENT_INFO_VQ clientBeingChecked = clients_in->data[i]->Clients[j];
			if (clientBeingChecked == NULL)
			{
				perror("\nmalloc failure!!");
				exit(1);
			}
            DWORD checkMe = (DWORD)clientBeingChecked->ClientIpAddress;

            if (((inIP & checkMe) == inIP) && ((inIP ^ checkMe) & ipMask) == 0)
            {
                // Ugh no I refuse to deep copy
                results->data[0]->Clients[results->data[0]->NumElements] = clientBeingChecked;
                results->data[0]->NumElements++;
            }
        }
    }
}

void searchClientListForMAC(const BYTE *MAC, const DWORD MAC_length, const DHCPClientList *clients_in, DHCPClientList *results)
{
    results->data[0]->NumElements = 0;
	results->count = 1;
    for (DWORD i = 0; i < clients_in->count; i++){
        for (DWORD j = 0; j < clients_in->data[i]->NumElements; j++){
            LPDHCP_CLIENT_INFO_VQ clientBeingChecked = clients_in->data[i]->Clients[j];
			if (clientBeingChecked == NULL){
				// TODO: error handling motherfucker, do you speak it
				perror("\nmalloc failure!!");
				exit(1);
			}
            BYTE* checkMe = clientBeingChecked->ClientHardwareAddress.Data;

            if (findBYTESubstring((char*)MAC, MAC_length, (char*)checkMe, MAC_ADDRESS_LENGTH) > -1){
                // TODO: Ugh no I refuse to deep copy... or do I?
                results->data[0]->Clients[results->data[0]->NumElements] = clientBeingChecked;
                results->data[0]->NumElements++;
            }
        }
    }
    if (results->data[0]->NumElements < 1) {
        results->count = 0;
        memcpy(results->errorMAC, MAC, MAC_length);
    }

}

void printClients(DHCPClientList clients)
{
    if (clients.count < 1) {
        wprintf(L"\nNo results for mac: %02x:%02x:%02x:%02x:%02x:%02x",
               clients.errorMAC[0],
               clients.errorMAC[1],
               clients.errorMAC[2],
               clients.errorMAC[3],
               clients.errorMAC[4],
               clients.errorMAC[5]);
    }
    for (int i = 0; i < clients.data[0]->NumElements; i++){
        LPDHCP_CLIENT_INFO_VQ client = clients.data[0]->Clients[i];
		BYTE* byte = client->ClientHardwareAddress.Data;
		DWORD printedIP = 0;
		convertEndian(&client->ClientIpAddress, &printedIP);
		wprintf(
			L"\n%u.%u.%u.%u  %.02x:%.02x:%.02x:%.02x:%.02x:%.02x    %ls",  
			(unsigned int)(printedIP & 0xFF), (unsigned int)((printedIP >> 8) & 0xFF), (unsigned int)((printedIP >> 16) & 0xFF), (unsigned int)((printedIP >> 24) & 0xFF),
			byte[0], byte[1], byte[2], byte[3], byte[4], byte[5], 
			client->ClientName
        );
    }
}

DWORD getAllClientsFromDHCPServers(const Serverlist *servers, DHCPClientList *list)
{
    const int          ALL_SUBNETS      = 0;
    DHCP_RESUME_HANDLE resume           = 0;
    DWORD              totalClientsRead = 0;
    DWORD              clientsRead      = 0;
    DWORD              clientsTotal     = 0;
    list->count = 0;
    list->data = (LPDHCP_CLIENT_INFO_ARRAY_VQ*)calloc(100, sizeof(LPDHCP_CLIENT_INFO_ARRAY_VQ));
    for (DWORD j = 0; j < servers->length; j++){
        DWORD status = 0;
        do {
            status = DhcpEnumSubnetClientsVQ(&servers->list[j * SERVERNAME_LEN], ALL_SUBNETS, &resume, UINT_MAX, &list->data[list->count], &clientsRead, &clientsTotal);
            totalClientsRead += clientsRead;
            list->count++;
        } while (status == ERROR_MORE_DATA);
		wprintf(L"\n\nTotal found clients on %ls: %d", &servers->list[j * SERVERNAME_LEN], totalClientsRead);
		totalClientsRead = 0;
    }

    return ERROR_SUCCESS;
}

void cleanupUserList(DHCPClientList* list)
{
    if (list == NULL)
        return;
    if (list->data == NULL)
        return;
    for (int i = 0; i < list->count; i++){
        if (list->data[i] == NULL) {
            continue;
        }
        DhcpRpcFreeMemory(list->data[i]);
        //list->data[i] = NULL;
    }
    list->count = 0;
    free(list->data);
    list->data = NULL;
    list = NULL;
    return;
}
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
