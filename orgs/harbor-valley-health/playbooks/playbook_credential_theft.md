# PB-HVH-CRED-01 Credential Theft

Owner: Incident Response with IAM. Shared clinical workstations hold many cached credentials, so treat any dump as exposing every user who logged on to the host this shift.

## Applies to
LSASS access by non-system tools, comsvcs.dll MiniDump, procdump against lsass (T1003.001), Kerberoasting (T1558.003), any activity by a DISABLED privileged account.

## Response steps
- Contain the host.
- Reset passwords for every account with a session on the host this shift, including badge-tap SSO users.
- If an EHR database or domain account is involved, rotate service account secrets and review EHR audit logs for record access.

## SLA
IAM lead and IR lead notified within 30 minutes.
