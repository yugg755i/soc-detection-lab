
# Privileged Command Execution Playbook

## Alert Name

Privileged Command Execution

## Description

This alert triggers when a user executes a command using sudo.

## Detection Logic

```spl
index=main host="Ubuntu" "COMMAND="
```

## Investigation Steps

### 1. Identify User

Determine which user executed the privileged command.

### 2. Identify Executed Command

Review the command that was executed using sudo.

### 3. Verify Authorization

Determine whether the user was authorized to perform the action.

### 4. Assess Command Impact

Review whether the command could modify system configurations, create accounts, delete files, or otherwise affect system security.

### 5. Assess Severity

If the command was unauthorized or potentially malicious, escalate the investigation.

## Response Actions

* Investigate the user account.
* Review recent privileged activity.
* Disable the account if compromise is suspected.
* Escalate to a higher analyst tier if necessary.

## Severity

Medium

## MITRE ATT&CK

T1548 - Abuse Elevation Control Mechanism
