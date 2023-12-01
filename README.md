# dhcp-mac-hunter
Network analysis tool for Windows sysadmins

# Building
Open the solution in Visual Studio and make a Release Build.
The only external dependency required is libssh, which has it's own dependencies
like zlib and libssl.

# About
This software is for finding a device by MAC or IP on the entire network.
It can also list all devices connected to a Cisco IOS switch.

# How To Use
Write the addresses of the DHCP servers
into "servers.conf" separated by a newline each.
The source folder is not needed to run.
Launch the executable as an administrator of the DHCP server.

## Searching a MAC
Search a mac address by writing in the hex address without
any delimiters, e.g.: "00e0".
Partial MAC addresses will match the given bytes anywhere
in the full address.
It's case insensitive, 
only full octets are supported ("1a2b" works, "1a2" doesn't work)

## Searching an IP
Type in the ip address in decimal format, delimited by a period ".", e.g.: "10.10.255.2".
An incomplete address will return the entire scope e.g.: "10.10.255" 
will return all clients found in that address range.

## Searching a Switch
The software can also print out all hosts found connected to a cisco IOS
switch. It will log into the switch with SSH and search all the MAC addresses in DHCP.
It'll only ask for a username and password once, restart the program
to input it again.
Use this functionality with "t IP_ADDRESS".

## Refresh DHCP Data
The DHCP data needs to be refreshed manually.
Do this by inputting "r".

# Known Issues
- 1-2mb memory leak when refreshing DHCP data
- possible 200kb memory leak when seaching a switch?
