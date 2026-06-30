# SSH Brute Force Playbook

## Alert Name

SSH Brute Force

## Description

This alert identifies repeated failed SSH authentication attempts originating from a single source IP.

## Severity

High

## ATT&CK

* Technique: T1110.001 — Password Guessing
* Tactic: Credential Access

## Investigation Steps

### 1. Confirm the Failed Authentication Activity

Verify that the alert corresponds to repeated failed SSH login attempts.

Review:

* src_ip
* count
* host
* _time

Confirm that the threshold was exceeded.

### 2. Review the Source IP

Determine whether the source IP belongs to:

* Internal infrastructure
* An approved security assessment
* An external system

Review previous activity associated with the same IP address.

### 3. Identify Targeted Accounts

Review the usernames targeted during the attack.

Determine whether:

* A single account was targeted.
* Multiple usernames were attempted.

This may help distinguish password guessing from username enumeration.

### 4. Check for Successful Authentication

Search for successful SSH logins from the same source IP shortly after the failed attempts.

Successful authentication following multiple failures may indicate account compromise.

### 5. Investigate Related Activity

Review additional authentication events around the same timeframe.

Look for:

* Successful SSH logins
* User creation
* Privileged command execution
* Additional brute-force attempts
* Lateral movement

Determine whether the brute-force activity is part of a larger attack.

### 6. Determine the Triage Outcome

Classify the activity as one of the following:

* User password mistyping
* Authorized penetration testing
* Security assessment
* Suspicious activity requiring escalation

## Response Actions

* Verify whether the activity was authorized.
* Block or monitor malicious source IP addresses.
* Reset credentials if compromise is suspected.
* Investigate related authentication activity.
* Escalate confirmed attacks to the incident response team.

## Detection Tuning

Exclude approved security testing and vulnerability assessment systems where appropriate.

## False Positive Considerations

* Internal vulnerability scanners
* Authorized penetration testing
* User password mistakes
* Security validation exercises

## Validation

The playbook was validated using a simulated SSH brute-force attack from the Kali Linux attacker machine.
