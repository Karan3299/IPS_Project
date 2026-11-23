# IPS_Project
INTRUSION PREVENTION SYSTEM WITH DEEP PACKET INSPECTION
Using Python and Scapy

Project Type:
Educational Cyber Security Project

Main File:
ips_core.py

Technologies Used:
- Python
- Scapy
- Kali Linux
- iptables

Main Features:
1. TCP Telnet traffic detection on port 23.
2. Basic port scan detection using unique destination ports.
3. Basic SQL injection signature detection using raw packet payloads.
4. Incident logging in ips_incident.log.
5. Attempts to block detected source IP addresses using iptables.

Execution:
sudo python3 ips_core.py

Note:
The project was developed and tested in a controlled Kali Linux
environment. The firewall-related functionality requires appropriate
Linux privileges.
