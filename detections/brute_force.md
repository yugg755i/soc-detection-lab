# Brute Force Detection

## Objective

Detect multiple failed SSH login attempts against a user account.

## Data Source

Ubuntu auth.log forwarded through Splunk Universal Forwarder.

## SPL Query

```
index=main host="Ubuntu" "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count >= 10
```

## Attack Simulation 

Hydra was used from the Kali VM to generate multiple failed SSH logins against the Ubuntu server. 

## Detection Logic

Splunk searches for failed SSH authentication events, extracts source IP address using a regular expression, and counts the number of failed logins for each source IP. If the number of failed attempts exceeds the defined threshold, the activity is flagged as a potential brute-force attack.

## Expected Output

Generate an alert when a source IP exceeds the failed login threshold, which indicates a potential brute-force attack on the Ubuntu server.
