
# Privileged Command Execution Detection

## Objective

Detect the execution of privileged commands using sudo.

## Data Source

Ubuntu auth.log forwarded through Splunk Universal Forwarder.

## SPL Query

```spl
index=main host="Ubuntu" "COMMAND="
```

## Attack Simulation

Administrative commands were executed using sudo on the Ubuntu server.

## Detection Logic

Splunk searches for sudo activity within the authentication logs. Events containing executed commands are identified and monitored to provide visibility into privileged actions performed by users. Excessive or unexpected administrative activity may indicate malicious behavior or misuse of privileges.

## Expected Output

Generate an alert whenever a privileged command is executed using sudo on the Ubuntu server.
