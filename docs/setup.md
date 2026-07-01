# Environment Setup

## Overview

This document describes the environment used to build the SOC Detection Lab and the steps required to reproduce it.

The lab consists of a centralized Splunk Enterprise instance running on an Arch Linux host with Windows and Linux endpoints forwarding security telemetry through Splunk Universal Forwarders. The environment is designed to support attack simulation, detection engineering, alert validation, dashboard development, and analyst playbooks.

---

# Lab Architecture

| Component | Purpose |
|-----------|---------|
| Arch Linux | Host operating system running Splunk Enterprise and virtual machines |
| QEMU/KVM | Virtualization platform |
| Windows 10 | Endpoint generating Sysmon and Windows Security telemetry |
| Ubuntu Server | Linux endpoint generating authentication and administrative logs |
| Kali Linux | Attacker system used for controlled attack simulations |
| Splunk Enterprise | Centralized log collection, detection, alerting, and visualization |
| Splunk Universal Forwarder | Log forwarding from endpoints to Splunk |

---

# Prerequisites

The following software is required:

- Arch Linux
- QEMU/KVM
- Windows 10
- Ubuntu Server
- Kali Linux
- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon

---

# Environment Setup

## 1. Install Splunk Enterprise

Install Splunk Enterprise on the Arch Linux host.

After installation:

- Start the Splunk service.
- Configure the management account.
- Verify access through the web interface.
- Enable receiving on port `9997` (Settings → Forwarding and receiving → Configure receiving → Add new). This is required before any forwarder can send data.

Telemetry will be indexed into Splunk's default `main` index — no index creation is required.

---

## 2. Create Virtual Machines

Create the following virtual machines:

### Windows 10

Purpose:

- Generate Windows endpoint telemetry.

Install:

- Splunk Universal Forwarder
- Sysmon

---

### Ubuntu Server

Purpose:

- Generate Linux authentication telemetry.

Install:

- Splunk Universal Forwarder

---

### Kali Linux

Purpose:

- Execute attack simulations against the Ubuntu Server and Windows 10 endpoints.

No Splunk components are required on this system.

---

# Configure Log Forwarding

## Ubuntu Server

Configure the Splunk Universal Forwarder to monitor:

```text
/var/log/auth.log
```

Forward events to the Splunk Enterprise server.

Verify that authentication events appear within:

```spl
index=main host="ubuntuserver"
```

---

## Windows 10

Install Sysmon using an appropriate configuration file.

Configure the Splunk Universal Forwarder to monitor:

- Microsoft-Windows-Sysmon/Operational
- Security

Verify telemetry using:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

and

```spl
index=main source="WinEventLog:Security"
```

---

# Verify Telemetry

Confirm that both Linux and Windows events are successfully indexed.

Example Linux search:

```spl
index=main host="ubuntuserver"
```

Example Windows Sysmon search:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

Example Windows Security search:

```spl
index=main source="WinEventLog:Security"
```

---

# Detection Validation

After confirming telemetry ingestion, execute the attack simulations documented in each detection.

Examples include:

## Linux

- SSH brute force
- Password guessing
- Username enumeration
- User creation
- Privileged command execution

## Windows

- CMD execution
- PowerShell execution
- Encoded PowerShell
- LOLBin execution
- Scheduled task creation
- Service creation
- Local user creation

Each simulation should produce telemetry that matches its corresponding SPL detection.

---

# Alerts

Create a scheduled alert for every documented detection.

Each alert should:

- Execute on a scheduled interval
- Trigger when the detection returns results
- Generate a notable event for analyst review

Alert configuration screenshots are included within each detection document.

---

# Dashboard

Import or recreate the Dashboard Studio dashboard described in `docs/dashboards.md`.

The dashboard provides:

- Environment summary KPIs
- Linux authentication monitoring
- Windows endpoint monitoring
- Detection summaries
- Investigation tables

---

# Validation Checklist

Verify the following before considering the lab complete:

- Splunk Enterprise is operational and receiving on port 9997.
- All virtual machines are running.
- Ubuntu authentication logs are forwarded.
- Windows Sysmon events are forwarded.
- Windows Security events are forwarded.
- Every SPL detection returns expected telemetry.
- Alerts trigger successfully.
- Dashboard panels populate correctly.
- Detection documentation includes screenshots.
- Analyst playbooks match the implemented detections.

---

# Related Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Overall lab architecture |
| [Workflow](workflow.md) | Detection validation workflow |
| [Telemetry](telemetry.md) | Collected telemetry |
| [Detections](detections.md) | Detection catalog |
| [Dashboards](dashboards.md) | Dashboard implementation |

---

# Summary

The SOC Detection Lab provides a reproducible environment for developing and validating security detections across Windows and Linux platforms. By combining Splunk Enterprise, Sysmon, Windows Security logs, Ubuntu authentication logs, and controlled attack simulations, the lab demonstrates a complete detection engineering workflow from telemetry collection through alerting, dashboard visualization, and analyst investigation.
