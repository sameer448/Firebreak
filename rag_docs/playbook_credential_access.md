# PB-CRED-01 Credential Access Response

Owner: Incident Response. Severity guidance and steps below are mandatory for this alert category.

## Applies to
Credential dumping (T1003), LSASS access by non-system tools, comsvcs.dll MiniDump, and Kerberoasting (T1558.003: bursts of RC4 service-ticket requests, tools such as Rubeus).

## Response steps
- Contain the host with EDR network isolation.
- Reset passwords for every account with a session on the host and revoke refresh tokens.
- If a domain controller or Tier-0 account is involved, page the IR on-call and plan a double krbtgt reset.
- Preserve dump files as evidence before deletion.

## SLA
IR lead notified within 30 minutes.

## Additional guidance
Kerberoasting: identify every service account whose ticket was requested, rotate those passwords to 25+ characters, and move service accounts to gMSA where possible.
