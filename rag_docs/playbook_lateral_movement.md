# PB-LAT-01 Lateral Movement and Domain Reconnaissance

Owner: Incident Response. Severity guidance and steps below are mandatory for this alert category.

## Applies to
PsExec-style remote service creation, admin-share access, burst domain reconnaissance, use of disabled or offboarded accounts.

## Response steps
- Isolate the source and all destination hosts.
- Disable the account used.
- If a domain controller received remote execution, declare a Severity 1 incident and engage the external IR retainer.
- Review 7 days of logons for the account.

## Additional guidance
Disabled or offboarded accounts showing activity: treat as credential compromise and reset krbtgt if the account was privileged.
