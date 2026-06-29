# Local User Creation Playbook

## Alert Name

Local User Creation

## Description

This alert identifies the creation of a new local user account using Windows Security Event ID 4720.

## Severity

High

## ATT&CK

**Technique**

* T1136.001 — Create Account: Local Account

**Tactic**

* Persistence

## Investigation Steps

### 1. Confirm the Account Creation

Verify that the alert corresponds to a successful local user account creation.

Review:

* Account_Name
* SAM_Account_Name
* Account_Domain

Identify the newly created account.

### 2. Identify Who Created the Account

Review the following fields:

* SubjectUserName
* SubjectDomainName
* LogonId

Determine which user or administrator created the account.

### 3. Review the Created Account

Determine whether the account follows organizational naming conventions.

Review:

* Account_Name
* UserAccountControl
* Account_Domain

Identify unusual usernames, privileged accounts, or accounts created outside normal provisioning procedures.

### 4. Investigate Related Activity

Review events occurring around the same timestamp.

Look for:

* Account added to privileged groups (Event ID 4732 or 4728)
* Password changes
* Privilege assignment events
* Sysmon Process Creation (Event ID 1) showing `net.exe`, `powershell.exe`, or other account management tools

Determine how the account was created and whether additional malicious activity occurred.

### 5. Verify User Context

Determine whether the administrator responsible for creating the account was authorized to perform account provisioning.

Review recent administrative activity from the same user.

### 6. Determine the Triage Outcome

Classify the activity as one of the following:

* Approved administrative account creation
* Automated provisioning
* Security testing
* Suspicious persistence requiring escalation

## Response Actions

* Confirm whether the account creation was authorized.
* Disable or remove unauthorized accounts.
* Reset credentials if compromise is suspected.
* Investigate additional persistence mechanisms.
* Escalate confirmed unauthorized account creation to the incident response team.

## Detection Tuning

Exclude approved provisioning systems and authorized administrative account creation where appropriate.

## False Positive Considerations

* IT administrators
* Help desk provisioning
* Automated deployment tools
* Identity management solutions

## Validation

The playbook was validated by creating a local user account using the `net user` command and confirming that Windows Security Event ID 4720 was successfully ingested into Splunk.
