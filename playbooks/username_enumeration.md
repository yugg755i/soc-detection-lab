
# Username Enumeration Detection Playbook

## Alert Name

Username Enumeration Detection

## Description

This alert triggers when multiple authentication attempts are made using invalid usernames.

## Investigation Steps

### 1. Identify Source IP

Review the source IP responsible for the enumeration activity.

### 2. Review Invalid Usernames

Determine which usernames were targeted during the attack.

### 3. Count Enumeration Attempts

Review the number of invalid username attempts.

### 4. Check for Valid Username Activity

Determine whether the source IP later attempted valid usernames or successful logins.

### 5. Assess Severity

If the activity appears targeted or persistent, escalate the investigation.

## Response Actions

* Investigate source IP.
* Monitor for additional authentication activity.
* Block source IP if malicious activity continues.
* Escalate if reconnaissance activity persists.

## Severity

Medium

## MITRE ATT&CK

Related ATT&CK tactic: Reconnaissance
