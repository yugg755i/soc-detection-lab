
# SSH Brute Force Detection Playbook

## Alert Name

SSH Brute Force Detection

## Description

This alert triggers when a source IP generates 10 or more failed SSH login attempts.

## Detection Logic

```spl
index=main host="Ubuntu" "failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count >= 10
```

## Investigation Steps

### 1. Identify Source IP

Review the source IP responsible for the failed login attempts.

Example:

192.168.100.10

### 2. Count Failed Attempts

Determine how many authentication failures occurred.

### 3. Identify Targeted User(s)

Review which usernames were targeted during the attack.

Example:

ubuntu
root
fakeuser

### 4. Check for Successful Authentication

Search for successful SSH logins after the failed attempts.

### 5. Assess Severity

If successful login follows repeated failures, escalate investigation.

## Response Actions

- Investigate source host.
- Block malicious IP if external.
- Disable compromised account if necessary.
- Escalate to higher analyst tier.

## Severity

High

## MITRE ATT&CK

T1110 - Brute Force
