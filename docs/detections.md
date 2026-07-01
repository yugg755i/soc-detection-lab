# Detection Catalog

## Overview

This document provides an overview of every detection implemented in the SOC Detection Lab.

Each detection was developed using telemetry generated through controlled attack simulations and validated against events collected by Splunk Enterprise. Detailed documentation for every detection is available in the `detections/` directory, while investigation procedures are documented separately in the corresponding analyst playbooks.

The current detection set covers both Linux authentication activity and Windows endpoint telemetry, providing visibility into common attacker techniques including execution, persistence, privilege escalation, credential attacks, and reconnaissance.

## Detection Coverage

| Detection | Platform | Data Source | ATT&CK Technique | ATT&CK Tactic |
|-----------|----------|-------------|------------------|---------------|
| PowerShell Execution | Windows | Sysmon Event ID 1 | T1059.001 | Execution |
| Encoded PowerShell | Windows | Sysmon Event ID 1 | T1059.001 | Execution |
| CMD Execution | Windows | Sysmon Event ID 1 | T1059.003 | Execution |
| LOLBin Execution | Windows | Sysmon Event ID 1 | T1218, T1105, T1197 | Defense Evasion, Execution, Command and Control |
| Scheduled Task Creation | Windows | Sysmon Event ID 1 | T1053.005 | Execution, Persistence, Privilege Escalation |
| Service Creation | Windows | Sysmon Event ID 1 | T1543.003 | Persistence, Privilege Escalation |
| Local User Creation | Windows | Security Event ID 4720 | T1136.001 | Persistence |
| SSH Brute Force | Linux | auth.log | T1110.001 | Credential Access |
| Password Guessing Success | Linux | auth.log | T1110.001 | Credential Access |
| Username Enumeration | Linux | auth.log | T1589.001 | Reconnaissance |
| User Creation | Linux | auth.log | T1136.001 | Persistence |
| Privileged Command Execution | Linux | auth.log | T1548.003 | Privilege Escalation |

## Detection Categories

### Linux Authentication Monitoring

These detections monitor authentication and administrative activity collected from the Ubuntu authentication log.

- SSH Brute Force
- Password Guessing Success
- Username Enumeration
- User Creation
- Privileged Command Execution

### Windows Endpoint Monitoring

These detections monitor Windows process creation and security auditing events collected through Sysmon and Windows Security logs.

- PowerShell Execution
- Encoded PowerShell
- CMD Execution
- LOLBin Execution
- Scheduled Task Creation
- Service Creation
- Local User Creation

## Detection Development Workflow

Each detection follows the same development lifecycle:

1. Simulate attacker activity.
2. Generate endpoint telemetry.
3. Verify log ingestion into Splunk.
4. Develop and validate the SPL query.
5. Configure a scheduled alert.
6. Create an analyst playbook.
7. Integrate the detection into the SOC dashboard.
8. Document screenshots and validation results.

This workflow ensures that every documented detection is supported by validated telemetry rather than theoretical search logic.

## Related Documentation

| Document | Purpose |
|----------|---------|
| [`architecture.md`](architecture.md) | Overview of the SOC Detection Lab architecture |
| [`workflow.md`](workflow.md) | Detection validation workflow |
| [`telemetry.md`](telemetry.md) | Overview of collected telemetry |
| [`dashboards.md`](dashboards.md) | Dashboard implementation |
| [`setup.md`](setup.md) | Environment deployment and configuration |
| [`README.md`](../README.md) | Project overview |


## Summary

The SOC Detection Lab currently includes twelve production-style detections spanning Linux authentication monitoring and Windows endpoint telemetry. Together, these detections provide coverage for common attacker behaviors across execution, credential access, reconnaissance, persistence, privilege escalation, defense evasion, and command-and-control techniques. Each detection is supported by validated telemetry, a corresponding Splunk alert, an analyst playbook, and dashboard visualizations.
