# PB-HVH-EXFIL-01 Possible PHI Exfiltration

Owner: Incident Response with the HIPAA Privacy Officer.

## Applies to
Large uploads to cloud storage (T1567), rclone or renamed sync tools, archive-and-transfer of EHR exports or imaging studies, unusual outbound volume from EHR or PACS servers.

## Response steps
- Block the destination at the proxy and contain the host.
- Identify which records or studies were in the transferred paths.
- The HIPAA Privacy Officer starts the breach risk assessment; breach notification decisions follow HIPAA timelines (without unreasonable delay, no later than 60 days).

## SLA
Privacy Officer engaged within 1 hour of confirmation.
