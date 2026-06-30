# User Creation Playbook

## Alert Name

User Creation

## Description

This alert identifies the creation of new local user accounts on the Ubuntu server.

## Severity

High

## ATT&CK

* Technique: T1136.001 — Local Account
* Tactic: Persistence

## Investigation Steps

### 1. Confirm the User Creation Event

Verify that the alert corresponds to a newly created local user account.

Review:

* host
* _time
* _raw

Identify the newly created username.

### 2. Identify the Account Creator

Determine which administrator or process created the account.

Review related authentication events to identify the originating user.

### 3. Verify Authorization

Determine whether the account creation was:

* Expected administrative activity
* Part of user onboarding
* Automated provisioning
* Unauthorized

### 4. Investigate Related Activity

Review surrounding events for:

* Successful SSH logins
* Privileged command execution
* Additional account creation
* Group membership modifications

Determine whether the account creation is part of a larger attack.

### 5. Determine the Triage Outcome

Classify the activity as one of the following:

* Expected administrative activity
* Authorized provisioning
* Security testing
* Suspicious activity requiring escalation

## Response Actions

* Verify whether the account creation was authorized.
* Disable unauthorized accounts.
* Investigate the originating administrator account.
* Review related administrative activity.
* Escalate confirmed unauthorized account creation.

## Detection Tuning

Exclude approved provisioning systems and configuration management tools where appropriate.

## False Positive Considerations

* User onboarding
* Administrator account management
* Automated provisioning
* Configuration management software

## Validation

The playbook was validated by creating a local user account on the Ubuntu server using the `useradd` command.
