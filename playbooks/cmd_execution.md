# CMD Execution Playbook

## Alert Name

CMD Execution

## Description

This alert identifies the execution of the Windows Command Prompt (`cmd.exe`) using Sysmon Process Creation events.

## Severity

Medium

## ATT&CK

**Technique**

* T1059.003 — Windows Command Shell

**Tactic**

* Execution

## Investigation Steps

### 1. Confirm the Process Execution

Verify that the alert corresponds to a Command Prompt process execution.

Review:

* Image
* OriginalFileName
* ProcessId

Confirm that the executable is the legitimate Windows Command Prompt (`cmd.exe`).

### 2. Review the Command Line

Inspect the `CommandLine` field.

Determine what command was executed.

Look for suspicious commands such as:

* `net user`
* `net localgroup`
* `sc.exe`
* `schtasks.exe`
* `reg.exe`
* `powershell.exe`
* `certutil.exe`

Simple commands like `whoami` or `hostname` are generally low risk, while administrative or reconnaissance commands may warrant further investigation.

### 3. Identify the Parent Process

Review the `ParentImage` field.

Determine what launched Command Prompt.

Common legitimate parent processes include:

* `explorer.exe`
* `WindowsTerminal.exe`
* `powershell.exe`

Unexpected parent processes (such as Microsoft Office applications, web browsers, or scripting engines) may indicate suspicious activity.

### 4. Verify the User Context

Review the `User` field.

Determine whether the user is expected to execute Command Prompt as part of their normal responsibilities.

### 5. Investigate Related Activity

Review additional events occurring around the same timestamp.

Look for:

* PowerShell executions
* Network connections (Sysmon Event ID 3)
* File creation (Sysmon Event ID 11)
* Registry modifications
* Child processes spawned by `cmd.exe`

Determine whether the Command Prompt execution is part of a larger attack chain.

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
* Escalate if Command Prompt execution appears suspicious or unauthorized.

## Detection Tuning

Exclude approved administrative scripts, enterprise management software, and automated maintenance tasks where appropriate.

## False Positive Considerations

Potential false positives include:

* System administrators
* IT automation
* Software installation processes
* Configuration management tools
* Approved maintenance scripts

## Validation

The playbook was validated by launching Command Prompt on the Windows endpoint and executing basic commands while confirming that the corresponding Sysmon Process Creation events were successfully ingested into Splunk.
