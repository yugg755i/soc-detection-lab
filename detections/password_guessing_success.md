# Password Guessing Success

## Objective

Detect when a user successfully logs in after multiple login failures.

## Data Source

Ubuntu auth.log forwarded through Splunk Universal Forwarder.

## SPL Query

```
index=main host="Ubuntu" ("Failed password" OR "Accepted password")
| rex "for (?:invalid user )?(?<user>\S+)"
| eval status=if(searchmatch("Accepted password"), "Success", "Failure")
| stats count(eval(status="Success")) as success_count count(eval(status="Failure")) as failure_count by user
| where failure_count >= 5 and success_count > 0
```

## Attack Simulation

A user account was targeted with multiple failed SSH login attempts, followed by a successful authentication from the same account.

## Detection logic

Splunk searches for both failed and successful SSH authentication events. Events are grouped by username, and the number of successful and failed login attempts is calculated. If a user has more than five failed login attempts followed by at least one successful login, the activity is flagged as a potential password guessing success.

## Expected Output

Generate an alert when a user successfully authenticates after exceeding the failed login threshold, indicating a possible password guessing attack.
