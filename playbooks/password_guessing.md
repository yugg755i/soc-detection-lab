
# Password Guessing Success Playbook

## Alert Name

Password Guessing Success

## Description

This alert triggers when a user successfully authenticates after multiple failed SSH login attempts.

## Investigation Steps

### 1. Identify Affected User

Review the username associated with the successful authentication.

### 2. Review Failed Login Attempts

Determine how many failed authentication attempts occurred before the successful login.

### 3. Identify Source IP

Review the source IP responsible for the login attempts.

### 4. Review Post-Login Activity

Check for user creation, privileged commands, or other suspicious activity following the successful authentication.

### 5. Assess Severity

If the login was unauthorized or suspicious, escalate the investigation immediately.

## Response Actions

* Verify account ownership.
* Reset user credentials if compromise is suspected.
* Review recent activity performed by the account.
* Escalate to higher analyst tier if necessary.

## Severity

High

## MITRE ATT&CK

T1110 - Brute Force
