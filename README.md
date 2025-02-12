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
**NTFS**

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

**Windows\System32**

C:\Windows traditionally contains the OS. This is where the environmental variables are. The system environment variable for the Windows directory is <i>%windir%</i>.

System32 folder holds all the critical files for the OS.

**User Accounts, Profiles, & Permissions**

User account type can either be: 
+ <i>administrator</i> - can make changes to the system (e.g. add users, delete users, modify groups, modify system settings, etc)
+ <i>standard user</i> - can only make change to folders/files attributed to the user

Running <i>lusrmgr.msc</i> will open the <i>Local User and Group Management</i>.

<i>User Account Control (UAC)</i> - prompts confirmation from the admin user when an operation requiring higher-level privileges needs to execute

## MSConfig
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

## Windows Security
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

## Networking Basics
<i>Networks</i> are the connections between technological devices. These can be formed from two devices to billions. A network can be one of two types:
+ Private
+ Public

The <i>Internet</i> is simply a giant network that consists of many smaller networks. The first iteration was ARPANET in the 1960s, which then led to the creation of the World Wide Web (WWW). 

Devices have two identifiable fingerprints: 
+ <i>Internet Protocol (IP) Address</i> - identifies a host on a network; can be public or private; can be IPv4 or IPv6
+ <i>Media Access Control (MAC) Address</i> - unique 12 hexadecimal number that identifies vendor and unique address of the network interface

<i>Ping</i> determine the performance of connection between devices (e.g. if connection exists or is reliable). This uses the Internet Control Message Protocol (ICMP), where the time for packets to travel between devices is measured. **ping [IP address/website URL]**: command for ping


