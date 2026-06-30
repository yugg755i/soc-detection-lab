# Service Creation Playbook

## Alert Name

Service Creation

## Description

This alert identifies the creation of Windows services using Sysmon Process Creation events.

## Severity

High

## ATT&CK

* Technique: T1543.003 — Windows Service
* Tactic: Persistence, Privilege Escalation

## Investigation Steps

### 1. Confirm the Service Creation

Verify that the alert corresponds to a service creation event.

Review:

* Image
* OriginalFileName
* ProcessId

Confirm that the executable is `sc.exe`.

### 2. Review the Command Line

Inspect the `CommandLine` field.

Identify:

* Service name
* Binary path (`binPath`)
* Additional service configuration parameters

Determine whether the service launches a legitimate application or an unexpected executable.

### 3. Identify the Parent Process

Review the `ParentImage` field.

Determine what launched `sc.exe`.

Common legitimate parent processes include:

* cmd.exe
* powershell.exe
* services.exe

Unexpected parent-child relationships may indicate malicious activity.

### 4. Verify the User Context

Review the `User` field.

Determine whether the user is authorized to create Windows services.

### 5. Investigate Related Activity

Review additional events occurring around the same timestamp.

Look for:

* PowerShell execution
* CMD execution
* File creation (Sysmon Event ID 11)
* Network connections (Sysmon Event ID 3)
* Additional persistence mechanisms

Determine whether the service creation is part of a larger attack chain.

### 6. Determine the Triage Outcome

Classify the activity as one of the following:

* Expected administrative activity
* Authorized software installation
* Security testing
* Suspicious persistence requiring escalation

## Response Actions

* Confirm whether the service creation was authorized.
* Review the executable configured for the service.
* Remove unauthorized services.
* Investigate related endpoint activity.
* Escalate if malicious persistence is suspected.

## Detection Tuning

Exclude approved enterprise management software and legitimate software installers where appropriate.

## False Positive Considerations

* System administrators
* Software installation
* Enterprise management software
* Endpoint security products
* Approved automation

## Validation

The playbook was validated using simulated Windows service creation on the endpoint.
