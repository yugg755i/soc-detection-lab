# Password Guessing Success Playbook

## Alert Name

Password Guessing Success

## Description

This alert identifies successful SSH authentication following multiple failed login attempts for the same user.

## Severity

High

## ATT&CK

* Technique: T1110.001 — Password Guessing
* Tactic: Credential Access

## Investigation Steps

### 1. Confirm the Authentication Activity

Verify that the alert corresponds to a successful SSH authentication following multiple failed login attempts.

Review:

* user
* success_count
* failure_count
* host
* _time

Confirm that the configured threshold was exceeded.

### 2. Review the Affected User

Determine whether the account owner expected to log in during the observed timeframe.

Review previous authentication activity associated with the account.

### 3. Review the Source IP

Determine whether the source IP belongs to:

* Internal infrastructure
* An approved security assessment
* An external system

Review historical authentication activity from the same source.

### 4. Investigate Related Activity

Review activity immediately following the successful authentication.

Look for:

* Privileged command execution
* User creation
* Additional SSH logins
* File modifications
* Persistence mechanisms

Determine whether the authentication is part of a larger attack.

### 5. Determine the Triage Outcome

Classify the activity as one of the following:

* Authorized user activity
* Approved security testing
* Password reset validation
* Suspicious activity requiring escalation

## Response Actions

* Verify whether the authentication was authorized.
* Investigate the source IP.
* Reset credentials if compromise is suspected.
* Review all activity performed after the successful login.
* Escalate confirmed compromises to the incident response team.

## Detection Tuning

Exclude approved password auditing and authorized security assessments where appropriate.

## False Positive Considerations

* Internal penetration testing
* Authorized password auditing
* User password verification
* Security validation exercises

## Validation

The playbook was validated using a simulated password guessing attack from the Kali Linux attacker machine.
