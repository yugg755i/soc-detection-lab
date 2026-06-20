
# Setup Guide

## Overview

This lab simulates common Linux-based attack scenarios and demonstrates how security events can be collected, analyzed, and detected using Splunk Enterprise.

The environment consists of:

* Kali Linux VM (Attacker)
* Ubuntu Server VM (Victim)
* Splunk Enterprise (SIEM)
* Splunk Universal Forwarder (Log Collection)

---

## Environment Setup

### 1. Create Virtual Machines

Create the following virtual machines in VirtualBox:

* Kali Linux VM
* Ubuntu Server VM

Both VMs were configured with:

* NAT Adapter (Internet Access)
* Internal Network Adapter (VM-to-VM Communication)

---

### 2. Configure Network Connectivity

Assign IP addresses to allow communication between the VMs.

Example:

| System        | IP Address     |
| ------------- | -------------- |
| Kali Linux    | 192.168.100.10 |
| Ubuntu Server | 192.168.100.20 |

Verify connectivity using:

```bash
ping <target-ip>
```

---

### 3. Enable SSH on Ubuntu

Install and start OpenSSH Server on Ubuntu:

```bash
sudo apt update
sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl start ssh
```

Verify SSH access from Kali:

```bash
ssh username@192.168.100.20
```

---

### 4. Install Splunk Enterprise

Install Splunk Enterprise on the host system.

Configure receiving on port:

```text
9997
```

This port will receive logs from the Universal Forwarder.

---

### 5. Install Splunk Universal Forwarder

Install Splunk Universal Forwarder on the Ubuntu server.

Configure forwarding to the Splunk Enterprise instance.

Monitor:

```text
/var/log/auth.log
```

Forward logs to:

```text
<SPLUNK_SERVER_IP>:9997
```

---

### 6. Verify Log Ingestion

Confirm that authentication events are visible in Splunk.

Example search:

```spl
index=main host="Ubuntu"
```

---

## Attack Simulation

The following activities were performed from the Kali VM:

* SSH Brute Force
* Username Enumeration
* Password Guessing
* User Creation
* Privileged Command Execution

These actions generated security-relevant events inside Ubuntu authentication logs.

---

## Detection Development

Custom detections were created in Splunk to identify:

* SSH Brute Force Activity
* Password Guessing Success
* Username Enumeration
* New User Creation
* Privileged Command Execution

Alerts were configured based on detection thresholds.

---

## Dashboard Creation

A SOC dashboard was developed to visualize:

* Failed Login Attempts
* Successful Logins
* Source IP Activity
* Targeted Users
* User Creation Events
* Privileged Command Usage

---

## Architecture

Refer to:

```text
architecture/architecture.png
```

for the complete lab architecture diagram.
