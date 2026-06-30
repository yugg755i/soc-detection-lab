# Scheduled Task Creation Playbook

## Alert Name

Scheduled Task Creation

## Description

This alert identifies the creation of scheduled tasks using Sysmon Process Creation events.

## Severity

Medium

## ATT&CK

* Technique: T1053.005 — Scheduled Task/Job
* Tactic: Execution, Persistence, Privilege Escalation

## Investigation Steps

### 1. Confirm the Scheduled Task Creation

Verify that the alert corresponds to a scheduled task creation.

Review:

* Image
* OriginalFileName
* ProcessId

Confirm that the executable is `schtasks.exe`.

### 2. Review the Command Line

Inspect the `CommandLine` field.

Identify:

* Task Name (`/tn`)
* Command to Execute (`/tr`)
* Schedule (`/sc`)
* Start Time (`/st`)

Determine whether the scheduled task performs legitimate administrative actions or potentially malicious activity.

### 3. Identify the Parent Process

Review the `ParentImage` field.

Determine what launched `schtasks.exe`.

Common legitimate parent processes include:

* cmd.exe
* powershell.exe
* explorer.exe

Unexpected parent-child relationships may indicate suspicious activity.

### 4. Verify the User Context

Review the `User` field.

Determine whether the user is authorized to create scheduled tasks.

### 5. Investigate Related Activity

Review additional events occurring around the same timestamp.

Look for:

* PowerShell execution
* CMD execution
* Network connections (Sysmon Event ID 3)
* File creation (Sysmon Event ID 11)
* Additional persistence mechanisms

Determine whether the scheduled task is part of a larger attack chain.

### 6. Determine the Triage Outcome

Classify the activity as one of the following:

* Expected administrative activity
* Authorized automation
* Security testing
* Suspicious persistence requiring escalation

## Response Actions

* Confirm whether the scheduled task was intentionally created.
* Review the command configured to execute.
* Remove unauthorized scheduled tasks.
* Investigate related endpoint activity.
* Escalate if malicious persistence is suspected.

## Detection Tuning

Exclude approved enterprise management software and legitimate scheduled maintenance tasks where appropriate.

## False Positive Considerations

* System administrators
* Windows maintenance tasks
* Enterprise management software
* Backup software
* Approved automation

## Validation

The playbook was validated using simulated scheduled task creation on the Windows endpoint.
