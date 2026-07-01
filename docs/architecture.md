# Architecture

## Overview

The SOC Detection Lab is built around a centralized Splunk Enterprise instance running on an Arch Linux host. The lab simulates a small enterprise environment consisting of Windows and Linux endpoints that generate security telemetry, which is collected, indexed, and analyzed using Splunk.

The architecture was designed to support end-to-end detection engineering, including telemetry collection, SPL-based detections, scheduled alerts, dashboard visualization, and analyst playbooks.

## Architecture Diagram

![SOC Detection Lab Architecture](../diagrams/architecture.png)

## Components

| Component | Purpose |
|-----------|---------|
| Arch Linux Host | Hosts Splunk Enterprise and the virtualized lab environment using QEMU/KVM |
| Kali Linux VM | Attacker system used to execute controlled attack simulations |
| Ubuntu Server VM | Linux endpoint generating SSH authentication and administrative telemetry |
| Windows 10 VM | Windows endpoint generating Sysmon and Windows Security telemetry |
| Splunk Universal Forwarder | Collects endpoint telemetry and forwards logs to Splunk Enterprise |
| Splunk Enterprise | Centralized log collection, indexing, detection, alerting, and visualization platform |

## Data Sources

### Ubuntu Server

The Ubuntu endpoint forwards authentication and administrative logs generated through:

- `/var/log/auth.log`

These logs provide visibility into:

- SSH authentication failures
- Successful SSH authentication
- Username enumeration
- Privileged command execution
- Local user creation

### Windows 10

The Windows endpoint generates telemetry from:

- Microsoft Sysmon
- Windows Security Log

Primary event sources include:

- Sysmon Event ID 1 — Process Creation
- Security Event ID 4720 — User Account Creation

## Log Collection

Telemetry is collected using Splunk Universal Forwarders installed on both endpoints.

The forwarders transmit events to Splunk Enterprise, where they are indexed into:

```text
index=main
```

This centralized architecture enables searches, detections, alerts, dashboards, and analyst playbooks to operate against a single data source.

## Detection Pipeline

Once telemetry reaches Splunk Enterprise, it progresses through the following pipeline:

1. Event ingestion
2. Indexing
3. SPL detection execution
4. Scheduled alert generation
5. Dashboard visualization
6. Analyst investigation using playbooks

The complete validation workflow is documented separately in [`workflow.md`](workflow.md).

## Design Principles

The architecture was designed around the following objectives:

- Centralized log collection
- Cross-platform telemetry visibility
- Repeatable attack simulation
- Detection validation using real telemetry
- Separation of detections, alerts, dashboards, and playbooks
- Modular documentation for maintainability

## Repository Integration

Each architectural component maps directly to the repository structure:

| Document | Purpose |
|----------|---------|
| [`detections/`](../detections) | Detailed detection documentation |
| [`playbooks/`](../playbooks) | Analyst investigation procedures |
| [`workflow.md`](workflow.md) | Detection validation workflow |
| [`telemetry.md`](telemetry.md) | Overview of collected telemetry |
| [`dashboards.md`](dashboards.md) | Dashboard implementation |
| [`README.md`](../README.md) | Project overview |


## Summary

The SOC Detection Lab architecture provides a centralized environment for collecting, analyzing, and visualizing security telemetry across Linux and Windows endpoints. By combining Splunk Enterprise, Sysmon, Windows Security logs, Ubuntu authentication logs, and controlled attack simulations, the architecture supports a complete detection engineering workflow from telemetry generation through analyst investigation.
