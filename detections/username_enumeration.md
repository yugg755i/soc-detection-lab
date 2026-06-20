
# Username Enumeration Detection

## Objective

Detect repeated attempts to authenticate using invalid usernames.

## Data Source

Ubuntu auth.log forwarded through Splunk Universal Forwarder.

## SPL Query

```spl
index=main host="Ubuntu" "invalid user" 
| rex "for invalid user (?<user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats dc(user) as unique_usernames, values(user) as attempted_usernames by src_ip
| where unique_usernames >= 5
```

## Attack Simulation

Multiple SSH login attempts were performed using invalid usernames from the Kali attacker VM.

## Detection Logic

Splunk searches for authentication events containing invalid usernames, extracts the username using a regular expression, and counts the number of occurrences for each username. If the number of attempts exceeds the defined threshold, the activity is flagged as a potential username enumeration attack.

## Expected Output

Generate an alert when invalid username attempts exceed the defined threshold, indicating possible reconnaissance or username enumeration activity.
