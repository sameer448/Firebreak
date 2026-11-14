# PB-EXFIL-01 Data Exfiltration

Owner: Incident Response. Severity guidance and steps below are mandatory for this alert category.

## Applies to
Cloud sync tools uploading to unapproved remotes, large outbound transfers, archive staging.

## Response steps
- Block the destination at the egress firewall.
- Disable the account.
- Have the data owner classify the affected data.
- The privacy officer decides on breach notification within 72 hours.

## Additional guidance
Preserve tool configs and logs (for rclone: the config file and --log-file output) before cleanup.
