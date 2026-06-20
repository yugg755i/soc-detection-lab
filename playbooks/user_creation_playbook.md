
# User Creation Detection Playbook

## Alert Name

User Creation Detection

## Description

This alert triggers whenever a new user account is created on the Ubuntu server.

## Investigation Steps

### 1. Identify New User Account

Review the username of the newly created account.

### 2. Determine Account Creator

Identify which user or process created the account.

### 3. Verify Authorization

Determine whether the account creation was expected or approved.

### 4. Review Related Activity

Check for privileged command execution or suspicious authentication events around the same timeframe.

### 5. Assess Severity

If the account creation is unauthorized, escalate immediately.

## Response Actions

* Disable unauthorized account.
* Review recent administrative activity.
* Investigate the account creator.
* Escalate to higher analyst tier if necessary.

## Severity

High

## MITRE ATT&CK

T1136 - Create Account
