# Telemetry

## Overview

The SOC Detection Lab collects security telemetry from both Linux and Windows endpoints to simulate a small enterprise environment. Logs are forwarded to Splunk Enterprise where they are indexed, searched, correlated, and visualized through custom detections, alerts, and dashboards.

The lab intentionally focuses on high-value telemetry commonly used by SOC analysts during investigations.

## Linux Telemetry

### Ubuntu Authentication Log

```
/var/log/auth.log
```

Forwarded using Splunk Universal Forwarder.

Primary telemetry includes:

- Failed SSH authentication
- Successful SSH authentication
- Invalid usernames
- sudo command execution
- Local user creation

### Example Security Events

- Failed password
- Accepted password
- invalid user
- COMMAND=
- new user

## Windows Telemetry

### Sysmon

Source:

```
WinEventLog:Microsoft-Windows-Sysmon/Operational
```

Primary Event IDs:

| Event ID | Description |
|----------|-------------|
| 1 | Process Creation |

Process Creation events provide:

- Executable path
- Command line
- Parent process
- User
- Integrity level
- Process hashes

These events form the foundation of the Windows detections implemented in this lab.

### Windows Security Log

Source:

```
WinEventLog:Security
```

Primary Event IDs:

| Event ID | Description |
|----------|-------------|
| 4720 | User account created |

This event provides:

- Created account
- Creating user
- Domain
- Account attributes

## Telemetry Flow

```
Linux Endpoint
        │
        │
Windows Endpoint
        │
        ▼
Splunk Universal Forwarder
        │
        ▼
Splunk Enterprise
        │
        ▼
Searches
Detections
Alerts
Dashboard
Playbooks
```

## Detection Coverage

| Telemetry | Detection |
|-----------|-----------|
| Failed SSH authentication | SSH Brute Force |
| Failed + Successful SSH authentication | Password Guessing Success |
| Invalid usernames | Username Enumeration |
| sudo activity | Privileged Command Execution |
| Linux account creation | User Creation |
| Sysmon Process Creation | CMD Execution |
| Sysmon Process Creation | PowerShell Execution |
| Sysmon Process Creation | Encoded PowerShell |
| Sysmon Process Creation | LOLBin Execution |
| Sysmon Process Creation | Scheduled Task Creation |
| Sysmon Process Creation | Service Creation |
| Windows Security Event ID 4720 | Local User Creation |

## Field Usage

The detections in this repository primarily rely on the following fields:

### Linux

- host
- _time
- _raw
- source
- sourcetype

### Windows Sysmon

- Image
- CommandLine
- ParentImage
- User
- ProcessId
- IntegrityLevel
- Hashes

### Windows Security

- EventCode
- SubjectUserName
- Account_Name
- SAM_Account_Name
- ComputerName


## Summary

The telemetry collected within this lab provides visibility into authentication activity, process execution, privilege escalation, persistence mechanisms, and account management across Linux and Windows endpoints. This telemetry serves as the foundation for every detection, alert, dashboard visualization, and analyst playbook included in the repository.
