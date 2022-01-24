# RedvsBlueProject
Capstone Engagement
Assessment, Analysis, and Hardening of a Vulnerable System

Table of Contents

This document contains the following sections:
01
02
03
04
Network Topology
Red Team: Security Assessment
Blue Team: Log Analysis and Attack Characterization
Hardening: Proposed Alarms and Mitigation Strategies

Network Topology 
3








Network
Address Range: 192.168.1.0/24
Netmask:255.255.255.0
Gateway:192.168.1.1

Machines
IPv4:192.168.1.1
OS: Windows
Hostname: Hyper-V Manager

IPv4:192.168.1.105
OS: Linux
Hostname: Capstone

IPv4:192.168.1.8
OS: Kali-Linux 
Hostname:Kali

IPv4:192.168.1.100
OS: Linux
Hostname: ELK server


Network Topology

5
Red Team
Security Assessment


Recon: Describing the Target
Nmap identified the following hosts on the network:
Hostname
IP Address
Role on Network
Hyper-V azure Machine 
192.168.1.1
Host machine that gives virtual machine access to physical network to communicate between servers.
Capstone
192.168.1.105
Vulnerable target machine accessed using the apache web server
Kali-Linux
192.168.1.8
Attacking Machine
Elk Server
192.168.1.100
Monitors network through Kibanna

Vulnerability Assessment
The assessment uncovered the following critical vulnerabilities in the target:
Vulnerability
Description
Impact
Public Access via open port 80 CVE-2019-6579
An attacker with network access to the web server on port 80/TCP could execute systems command with administrative privileges. 
Easy discovery and access to files and Secret Folders.
 Path Traversal (Directory Traversal)
CWE-23
Path traversal aims to access files or directory that are stored outside the web root by manipulating variables that reference with ../ sequences. 
This vulnerability enables attacker to access secret files or hidden directories on the web server 
CWE-307: Improper Restriction of Excessive Authentication Attempts
The software does not implement sufficient measures to prevent multiple failed authentication attempts within in a short time frame, making it more susceptible to brute force attacks.
The attacker can easily to brute force to obtain password credentials.

Vulnerability Assessment
The assessment uncovered the following critical vulnerabilities in the target:
Vulnerability
Description
Impact
LFI Vulnerability
Local File Inclusion are vulnerabilities makes an attacker trick the web application into exposing or running files on the web server. 
The attacker can easily gain access to sensitive credentials and can read and/or execute files on the vulnerable server.
WebDAV Vulnerability
The attacker can upload a shell script through the webDAV vulnerability to gain access. 
Improper configuration can allow hackers modify website content, upload shell and gain access to web server. 
Simple Usernames
The usernames used are short and predictable.
The usernames are based on first names which can easily be obtained through social engineering.

Exploitation: Nmap Scan
Tools & Processes
Run nmap to scan for open ports on the target machine

01
02
Achievements
After the nmap scan, the results showed 4 hosts up with port  22/TCP and port 80/TCP being of particular interest to me.
03

Exploitation: Path Traversal (Directory Traversal)
CWE-23

Tools & Processes
Dirb is a web content scan that features scanning and attacking folder that is hidden within websites. 



01
02
Achievements
I found out there was two hidden directories within the web server. 


03

Exploitation: Brute Force Password
Tools & Processes
Using hydra which is preinstalled in Kali Linux (Attacker Machine) and a password list (rockyou.txt) to run a brute force attack on the vulnerable web server using an easy to guess username of ‘Ashton”

01
02
Achievements
The exploit revealed with a password of the username “ashton” which was “leopoldo”
03

Exploitation: LFI Vulnerability
Tools & Processes
The password from the brute force attack. I could access the server through WebDav. 

I used msfvenom to create  a payload onto the target machine (capstone server)

01
02
Achievements
Using the multi/handler exploit I could gain a shell access of the machine.
03

Blue Team
Log Analysis and Attack Characterization
13

Analysis: Identifying the Port Scan
[Insert Here]
Include a screenshot of Kibana logs depicting the port scan. 
The port scan started on October 28, 2021 at approximately 02:30:20 pm
There was about 72,291 packets (hits) sent from 192.168.1.8
The sudden peaks in the network traffic suggests it was port scan.

Analysis: Finding the Request for the Hidden Directory
[Insert Here]
Include a screenshot of Kibana logs depicting the request for the hidden directory. 
On October 28, 2021 at 02:39:00 pm approximately a little over 10,000 requests where made to access http://192.168.1.105/company_folders/secret_folder.
The /secret_folder contained instructions and a hash to access another employee’s (Ryan) credentials which was used to upload connect and upload mypayload.php to access the web server through webDav.

Analysis: Uncovering the Brute Force Attack
[Insert Here]
Include a screenshot of Kibana logs depicting the brute force attack.  
10,043 requests were made to the server.
The hydra command stopped sending all request as soon as the credentials obtained as they were all that was needed.

Analysis: Finding the WebDAV Connection
 
31 requests were made to access /webdav directory
the main files that were requested where the /webDav/passwd.dav and /webDAV/mypayload.php.

Blue Team
Proposed Alarms and Mitigation Strategies
18

Mitigation: Blocking the Port Scan
An alert should be sent when there are outrageous amount of requests to the server in a short space of time.


The threshold set should be a not more than 50 requests per minute.
Install firewall and ensure they are regularly patched to minimize new zero day attacks.
Install an Intrusion Prevention System (IPS) to detect port scans and shut them down.
Regular port scans to detect and close all open ports that are open.
Filter system to allow known IPs and block all other IPs from scanning the system. 


Mitigation: Finding the Request for the Hidden Directory
An alert would be sent for any access from any unauthorized IP or access.

The threshold would for any attempt to access the hidden folder.
The server containing the hidden folder should be partitioned and not allowed to be shared for public access.
Encrypt all data in the secret folder to protect data even in case folder is breached.
Remove the folder entirely from the server. 


Mitigation: Preventing Brute Force Attacks
An alert should be sent if ‘401 Unauthorized’ is returned on the server since such error indicates the request sent by the client lacks valid authentication credentials.

The threshold  set would be 5 attempts within half hour.

Temporarily lock accounts that have 5 unsuccessful attempts within 30 minutes and block permanently for 7 attempts.
Only IPs on whitelist would be allowed to attempt login
Usernames and password should be complex and passwords should be changed regularly with reuse of passwords not allowed.

Mitigation: Detecting the WebDAV Connection
An alert would be sent of any attempt to access the directory from any machine and/or IP that is not recognized by whitelisted IP addresses.

The threshold hold set would be one attempt to trigger the alert.
Access to this folder should not be allowed from web interface.

Firewall rule that prevents access to this folder from unauthorized machine or IP should be set up 


Mitigation: Identifying Reverse Shell Uploads
An alert set for all traffic moving overport 4444. 

Also any file being uploaded into /webDAV folder should trigger an alert.

The threshold should be set to 1 attempt.

Users who have access to /webDAV folder should be given read only access to prevent upload of payloads into the folder
Remove the ability to upload files to the directory over the web interface.
Block all addresses other than trusted IP addresses to access the /webDAV folder.
Ensure that all ports are blocked except the absolutely necessary ports.


