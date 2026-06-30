# Username Enumeration Playbook

## Alert Name

Username Enumeration

## Description

This alert identifies repeated SSH authentication attempts using multiple invalid usernames from a single source IP.

## Severity

Medium

## ATT&CK

* Technique: T1589.001 — Gather Victim Identity Information: Credentials
* Tactic: Reconnaissance

## Investigation Steps

### 1. Confirm the Enumeration Activity

Verify that the alert corresponds to repeated authentication attempts using invalid usernames.

Review:

* src_ip
* unique_usernames
* attempted_usernames
* host
* _time

Confirm that the username threshold was exceeded.

### 2. Review the Source IP

Determine whether the source IP belongs to:

* Internal infrastructure
* An approved security assessment
* An external system

Review previous authentication activity associated with the same IP address.

### 3. Analyze Attempted Usernames

Review the list of attempted usernames.

Determine whether the attacker targeted:

* Administrative accounts
* Service accounts
* Common usernames
* Randomly generated usernames

This helps identify reconnaissance patterns.

### 4. Investigate Related Activity

Review additional authentication events around the same timeframe.

Look for:

* Password guessing attempts
* SSH brute-force activity
* Successful SSH logins
* Privileged command execution
* User creation

Determine whether the enumeration is part of a larger attack chain.

### 5. Determine the Triage Outcome

Classify the activity as one of the following:

* Authorized penetration testing
* Security assessment
* Vulnerability scanning
* Suspicious activity requiring escalation

## Response Actions

* Verify whether the activity was authorized.
* Investigate the originating source IP.
* Monitor for continued authentication attempts.
* Block malicious source IPs if appropriate.
* Escalate confirmed reconnaissance activity.

## Detection Tuning

Exclude approved vulnerability scanners and penetration testing systems where appropriate.

## False Positive Considerations

* Internal vulnerability scanners
* Authorized penetration testing
* Security assessments
* Automated authentication testing

## Validation

The playbook was validated by performing SSH authentication attempts against multiple non-existent user accounts from the Kali Linux attacker machine.
