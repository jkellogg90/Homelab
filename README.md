# Homelab
This page describes my homelab. My lab is mostly used for learning new technologies in the security field but it's also used for self hosting services useful to me.


# Hardware
![Image](https://i.imgur.com/2TOsY4d.jpg)

**Hypervisor:** Intel NUC6i7KYK NUC: 64GB DDR4 RAM, i7-6770HQ, 1.5TB NVMe PCIe M.2 storage. 

**Firewall:** ASA-5506-X Firewall with Firepower IPS

**Network Attached Storage (NAS):** Synology DS218+ with 12TB storage (2x6TB) in a RAID1 configuration.

**Wireless:** Ubiquiti Unifi Ap-AC Lite

**Network Switch:** Cisco Catalyst 2960-L Switch

**Other:** Raspberry PI 3 + 4


# Virtual Machines
![Image](https://i.imgur.com/8cU8DQt.png)

**Bitwarden:** Self hosted password management solution

**Confluence:** Used for documenting my homelab and general notes. Also serves as an asset management system. 

**Cuckoo Sandbox:** Used for sandboxing malware samples. 

**Splunk:** Ingests logs from all servers and network devices for retention and security monitoring purposes. 

**OSSEC:** Host intrusion detection system (HIDS) for Linux and Windows systems. 

**Zabbix:** Used for infrastructure monitoring for all servers and network devices. I setup email alerts for when a device goes down or has high processor, memory, and disk space usage. 

**Nessus:** Used for weekly vulnerability scanning of devices on the internal network and virtual machines hosted in the cloud. Results sent as a PDF in an email. 

**Opencanary:** Honeypot to detect and alert on scanning.

**Pihole:** Used for DNS blacklisting. I have two of these for redunancy purposes; one physical and one virtual.

**Windows Domain:** Small windows domain for testing purposes. 

**Snorby:** Application for viewing IDS alerts. This looks at traffic being spanned from my switch. 

**Firepower Management Center:** Used for management of the firepower sensor. 

**Jumpbox**: Used for administrating servers and network devices.

**Unifi Controller**: Used for administrating wireless access point

# Cloud Virtual Machines
jkellogg90.com - I mostly use this for testing my network controls (IPS/FW). 

![Image](https://i.imgur.com/OTJnRXa.png)
