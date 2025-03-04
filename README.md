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

### Firewalls
A <i>firewall</i> is responsible for determining what traffic is allowed to enter and exit a network. An administrator can permit or deny traffic based on these factors:
+ Source of traffic
+ Destination of traffic
+ Destination port
+ Protocol being used

Firewalls can be cateogrised into:
+ Stateful - determines the behaviour of a device based on the entire connection
+ Stateless - determines whether individual packets are acceptable or not

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

A <i>Uniform Resource Locator (URL)</i> is used as an instruction on how to access a resource on the net. URLs have multiple parts. Take for example http://user:password@tryhackme.com:80/view-room?id=1#task3
+ Scheme - instructs on what protocol to use (e.g. HTTP, HTTPS, FTP)
+ User - some services require authentication to log in
+ Host - domain name or IP address of the server
+ Port - port you are going to connect to (e.g. TCP ports 80/8080 for HTTP, 443/8443 for HTTPS)
+ Path - file name or location of the resource
+ Query String - extra bits of information that can be sent to the requested path
+ Fragment - reference to a location on the actual page requested, commonly used for pages with long content

HTTP methods show the client's intended action when making HTTP requests. The most common include:
+ GET - used for getting information from a web server
+ POST - used for submitting data to the web server and potentially creating new records
+ PUT - used for submitting data to a web server to update information
+ DELETE - used for deleting information/records from a web server

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

<i>Headers</i> are additional bits of data you can send to the web server when making requests. 

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

## Websites
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

## HTML Injection
<i>HTML Injection</i> is a vulnerability that occurs when unfiltered user input is displayed on the page. If a website does not sanitise user input (i.e. filter malicious text input), users can submit HTML or JavaScript code, allowing them to control the page's appearance and functionality.

<i>Input sanitation</i> is a means to protect a website secure. 

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

### Scanning
Metasploit has a number of modules to scan open ports on the target system and network (e.g. search portscan). Note: you can also use nmap commands using the msfconsole prompt. 

For speedier scanning, Metasploit is not the first choice. However, it does provide useful modules for the following:
+ UDP service identification -> the <i>scanner/discover/udp_sweep</i> module allows to quickly identify services running over UDP (i.e. quick way to identify DNS/NetBIOS)
+ SMB scans -> auxiliary modules such as <i>smb_enumshares</i> and <i>smb_version</i> are especially useful in corporate networks

