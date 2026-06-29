# Encoded PowerShell Playbook

## Alert Name

Encoded PowerShell Execution

## Description

This alert identifies PowerShell processes that execute Base64-encoded commands using the `-enc` or `-EncodedCommand` parameter.

## Severity

High

## ATT&CK

* Technique: T1059.001 — PowerShell
* Tactic: Execution

## Investigation Steps

### 1. Confirm the Process Execution

Verify that the alert corresponds to a PowerShell process execution.

Review:

* Image
* OriginalFileName
* ProcessId

Confirm that the executable is a legitimate PowerShell binary (`powershell.exe`).

### 2. Review the Command Line

Inspect the `CommandLine` field.

Confirm that PowerShell was executed using either:

* `-enc`
* `-EncodedCommand`

Extract and decode the Base64 payload to determine the actual command that was executed.

### 3. Identify the Parent Process

Review the `ParentImage` field.

Determine what launched PowerShell.

Unexpected parent processes such as Microsoft Office applications, web browsers, scripting engines, or archive utilities may indicate malicious activity.

### 4. Verify the User Context

Review the `User` field.

Determine whether the user is expected to execute encoded PowerShell commands as part of normal administrative activity.

### 5. Investigate Related Activity

Review additional events occurring around the same timestamp.

Look for:

* Network connections (Sysmon Event ID 3)
* File creation (Sysmon Event ID 11)
* Registry modifications
* Child processes spawned by PowerShell
* Additional PowerShell executions

Determine whether the encoded command is part of a larger attack chain.

### 6. Determine the Triage Outcome

Classify the activity as one of the following:

* Authorized administrative activity
* Security testing
* Expected automation
* Suspicious activity requiring escalation

## Response Actions

* Decode and review the PowerShell payload.
* Confirm whether the execution was authorized.
* Investigate related endpoint activity.
* Review additional PowerShell executions from the same host.
* Escalate if the encoded command appears suspicious or unauthorized.

## Detection Tuning

Exclude approved administrative automation and enterprise management software that legitimately uses encoded PowerShell commands.

## False Positive Considerations

* IT automation
* Endpoint management tools
* Configuration management software
* Authorized security testing
* Legitimate administrative scripts

## Validation

The playbook was validated using a simulated Base64-encoded PowerShell command executed on the Windows endpoint.
