# PB-HVH-RANS-01 Ransomware on Clinical Systems

Owner: Incident Response with Clinical Engineering. Patient safety comes first: coordinate isolation of patient-care systems with the clinical-systems on-call.

## Applies to
Shadow copy deletion or resizing, recovery disabled with bcdedit, backup catalog deletion (T1490), mass file encryption (T1486) on EHR, PACS, pharmacy or nurse-station systems.

## Response steps
- Isolate affected hosts with EDR network containment, except life-critical devices: for those, segment at the switch with Clinical Engineering present.
- Activate downtime procedures (paper charting) for affected units.
- Preserve the encrypting binary and ransom note; do not reboot affected servers.
- Notify the CMO, the cyber-insurance carrier and legal counsel.

## SLA
Containment decision within 15 minutes; CMO informed within 30 minutes.
