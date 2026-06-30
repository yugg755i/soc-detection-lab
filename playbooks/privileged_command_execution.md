# Privileged Command Execution Playbook

## Alert Name

Privileged Command Execution

## Description

This alert identifies commands executed using `sudo` on the Ubuntu server.

## Severity

Medium

## ATT&CK

* Technique: T1548.003 — Sudo and Sudo Caching
* Tactic: Privilege Escalation

## Investigation Steps

### 1. Confirm the Privileged Command

Verify that the alert corresponds to a command executed with `sudo`.

Review:

* host
* _time
* _raw

Identify the executed command.

### 2. Review the Executing User

Determine which user executed the command.

Confirm whether the user is authorized to perform privileged administrative actions.

### 3. Assess the Command

Determine whether the command:

* Modified system configuration
* Created or deleted accounts
* Accessed sensitive files
* Changed permissions
* Installed software

Evaluate the potential impact.

### 4. Investigate Related Activity

Review surrounding events for:

* SSH logins
* Additional `sudo` commands
* User creation
* Authentication failures
* File modifications

Determine whether the command is part of a larger attack.

### 5. Determine the Triage Outcome

Classify the activity as one of the following:

* Expected administrative activity
* Authorized maintenance
* Security testing
* Suspicious activity requiring escalation

## Response Actions

* Verify whether the command execution was authorized.
* Review the executed command for malicious intent.
* Investigate the originating user account.
* Review related administrative activity.
* Escalate confirmed unauthorized privileged activity.

## Detection Tuning

Exclude approved administrative automation and scheduled maintenance where appropriate.

## False Positive Considerations

* System administrators
* Routine maintenance
* Configuration management tools
* Approved administrative scripts

## Validation

The playbook was validated by executing a privileged command using `sudo` on the Ubuntu server.
