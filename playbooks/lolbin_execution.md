# LOLBin Execution Playbook

## Alert Name

LOLBin Execution

## Description

This alert identifies the execution of common Windows Living-off-the-Land Binaries (LOLBins) using Sysmon Process Creation events.

## Severity

Medium

## ATT&CK

**Techniques**

- T1218 — System Binary Proxy Execution
- T1105 — Ingress Tool Transfer
- T1197 — BITS Jobs

**Tactics**

- Defense Evasion
- Execution
- Command and Control

## Investigation Steps

### 1. Confirm the Executed LOLBin

Review:

- Image
- OriginalFileName
- ProcessId

Confirm which LOLBin was executed (for example, `certutil.exe`, `mshta.exe`, `regsvr32.exe`, `rundll32.exe`, or `bitsadmin.exe`).

### 2. Review the Command Line

Inspect the `CommandLine` field.

Determine how the LOLBin was used.

Examples include:

- `certutil -urlcache`
- `certutil -decode`
- `mshta http://...`
- `regsvr32 /i`
- `rundll32 javascript:`
- `bitsadmin /transfer`

The command-line arguments often reveal the attacker's intent.

### 3. Identify the Parent Process

Review the `ParentImage` field.

Determine what launched the LOLBin.

Unexpected parent processes, such as Microsoft Office applications, browsers, scripting engines, or document viewers, should be investigated.

### 4. Verify the User Context

Review the `User` field.

Determine whether the execution is expected for that user.

### 5. Investigate Related Activity

Review additional events around the same timestamp.

Look for:

- Network connections (Sysmon Event ID 3)
- File creation (Sysmon Event ID 11)
- Registry modifications
- Additional process creation events
- Child processes spawned by the LOLBin

Determine whether the LOLBin execution is part of a larger attack chain.

### 6. Determine the Triage Outcome

Classify the activity as one of the following:

- Expected administrative activity
- Authorized automation
- Security testing
- Suspicious activity requiring escalation

## Response Actions

- Confirm whether the execution was authorized.
- Review the command-line arguments.
- Investigate related endpoint activity.
- Isolate the endpoint if malicious behavior is confirmed.
- Escalate to the incident response team if necessary.

## Detection Tuning

Exclude approved administrative tools and enterprise software where appropriate.

## False Positive Considerations

- IT administration
- Software deployment
- Enterprise automation
- Backup software
- Security products

## Validation

The playbook was validated using simulated LOLBin execution on the Windows endpoint.
