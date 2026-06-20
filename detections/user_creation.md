
# User Creation Detection

## Objective

Detect the creation of new user accounts on the Ubuntu server.

## Data Source

Ubuntu auth.log forwarded through Splunk Universal Forwarder.

## SPL Query

```spl
index=main host="Ubuntu" "new user"
```

## Attack Simulation

A new user account was created on the Ubuntu server using administrative privileges.

## Detection Logic

Splunk searches for user creation events in the authentication logs. Any event indicating the creation of a new user account is identified and monitored, as unauthorized account creation may indicate persistence or privilege misuse.

## Expected Output

Generate an alert whenever a new user account is created on the Ubuntu server.
