# PowerShell Execution Playbook

## Alert Name

PowerShell Execution

## Description

This alert identifies the execution of PowerShell processes using Sysmon Process Creation events.

## Severity

Medium

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

Confirm that the executable is a legitimate PowerShell binary (`powershell.exe` or `pwsh.exe`).

### 2. Review the Command Line

Inspect the `CommandLine` field to determine how PowerShell was executed.

Look for suspicious arguments such as:

* `-EncodedCommand`
* `-ExecutionPolicy Bypass`
* `-NoProfile`
* `-WindowStyle Hidden`
* `-Command`

These parameters may indicate attempts to evade detection or execute malicious scripts.

### 3. Identify the Parent Process

Review the `ParentImage` field.

Determine what launched PowerShell.

Common legitimate parents include:

* explorer.exe
* cmd.exe
* Windows Terminal

Unexpected parent processes (such as Office applications, browsers, or scripting engines) may warrant further investigation.

### 4. Verify the User Context

Review the `User` field.

Determine whether the user is expected to execute PowerShell as part of their normal responsibilities.

### 5. Investigate Related Activity

Review additional events occurring around the same timestamp.

Look for:

* Network connections (Sysmon Event ID 3)
* File creation (Sysmon Event ID 11)
* Registry modifications
* Additional PowerShell executions
* Child processes spawned by PowerShell

Determine whether the PowerShell execution is part of a larger attack chain.

### 6. Determine the Triage Outcome

Classify the activity as one of the following:

* Expected administrative activity
* Authorized automation
* Security testing
* Suspicious activity requiring escalation

## Response Actions

* Confirm whether the execution was authorized.
* Review the executed command.
* Investigate related endpoint activity.
* Escalate if PowerShell execution appears suspicious or unauthorized.

## Detection Tuning

Exclude approved administrative scripts and enterprise management software where appropriate.

## False Positive Considerations

* System administrators
* IT automation
* Configuration management tools
* Monitoring agents
* Approved maintenance scripts

## Validation

The playbook was validated using simulated PowerShell execution on the Windows endpoint.
