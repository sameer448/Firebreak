# HVH Known False Positives

Owner: SOC. Recurring benign activity at Harbor Valley Health.

## Imaging vendor remote support
The PACS vendor's signed remote-support agent connects to PACS Imaging Servers during scheduled maintenance windows posted in the change calendar. The same tool on a nurse-station workstation is not approved.

## Nightly EHR backup
svc-backup runs vssadmin list shadows and wbadmin start backup on EHR Servers between 01:00 and 03:00. Deleting shadow copies or disabling recovery is never part of the backup job.

## Clinical workstation kiosk resets
Nurse-station workstations run a signed kiosk reset script at shift change (07:00, 19:00) that clears user profiles. It does not touch credential stores or LSASS.
