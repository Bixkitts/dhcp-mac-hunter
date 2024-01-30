# dhcp-mac-hunter
Network analysis tool for Windows sysadmins

# Building
Open the solution in Visual Studio and make a Release Build.
The only external dependency required is libssh version 0.10.x.
Preferably install the latest version with vcpkg on windows and
activate the include headers and the project should compile.
vcpkg should then install all of libssh's dependecies along with
libssh itself.

# About
This software is for finding a device by MAC or IP on the entire network.
It can also list all devices connected to a Cisco IOS switch.

# How To Use
Write the addresses of the DHCP servers
into a file called "servers.conf" in the same directory as the
executable separated by a newline each.
The source folder is not needed to run.
Launch the executable as an administrator of the DHCP server, AND SSH.
Open an issue if you urgently want proper SSH key auth.

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
Use this functionality with "t IP_ADDRESS".

## Refresh DHCP Data
The DHCP data needs to be refreshed manually.
Do this by inputting "r".

# Known Issues
- 1-2mb memory leak when refreshing DHCP data. I think this is microsoft's fault.

# Planned Features
## In descending order of importance...
- A clean and more robust codebase. I wrote this code as a quick dirty hack to get a project done but it has potential
  to be invaluable to the budding Windows sysadmin.
- At least a grep-like string search of results
- Better security
- Robustness in target platforms
- Finding MAC and IP addresses over SSH into switches

# Suggestions and Contributions
Open an issue on github,
or hit me up here or over email and help me write it.
It's currently a quick and dirty hack but with some help I'd be happy to turn this
into a proper tool.
(and check out the dev branch, almost every line is rewritten)
