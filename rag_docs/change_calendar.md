# Change Calendar and Scheduled Jobs

Owner: Change Advisory Board. Lists approved changes and recurring jobs that generate security-relevant activity. If activity is not listed here, no approved change covers it.

## CHG-48213: Patch deployment wave 2
Deploy KB5043187 to application servers via PsExec from JMP-ADM01, 01:00-04:00 UTC, every Wednesday in September 2026. Owner: Server Operations.

## CHG-48990: Firewall rule cleanup
Perimeter firewall rule cleanup, Saturday 22:00-02:00 UTC. Owner: network team.

## CHG-49102: SQL Server cumulative update
Cumulative update on SRV-SQL03 and SRV-SQL07, Sunday 01:00-03:00 UTC. Owner: database team.

## JOB-SQL-EXPORT: Nightly data export
Nightly xp_cmdshell copy of order, customer, and billing CSV exports from SRV-SQL07 to \\SRV-FILE02\Exports between 01:00 and 03:00 UTC. Owner: database team. Runs outside this window are not scheduled.

## JOB-SQL-REINDEX: Weekly index maintenance
Weekly index maintenance on SRV-SQL03, Sunday 02:00-04:00 UTC. Owner: database team.

## JOB-BACKUP-OFFSITE: Nightly offsite backup
Nightly-Offsite-Backup task on SRV-BKP servers, 01:00-05:00 UTC, rclone to corp-s3:corp-backups-prod only. Owner: infrastructure team.

## Share migration
Share-Migration robocopy waves from SRV-FILE-OLD to SRV-FILE servers, nightly 01:00-05:00 UTC until the end of Q3 2026. Owner: infrastructure team.
