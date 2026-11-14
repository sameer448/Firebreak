# PB-EVA-01 Defense Evasion

Owner: Incident Response. Severity guidance and steps below are mandatory for this alert category.

## Applies to
Defender real-time protection disabled, broad exclusions added, tampering with security tools.

## Response steps
- Isolate the host.
- Force an Intune policy sync to restore Defender settings and remove unauthorized exclusions.
- Run a full scan including previously excluded paths.
- Hunt fleet-wide for the same exclusion paths.

## Additional guidance
Exclusions added by anything other than the Intune AgentExecutor in Program Files (x86) are unauthorized.
