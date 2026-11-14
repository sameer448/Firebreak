# Approved Tools and Expected Administrative Activity

Owner: Security Engineering. Last reviewed: 2026-09-15. Any tool or behavior not listed here is unapproved on managed endpoints.

## SCCM-01: Configuration Manager client scripts
C:\Windows\CCM\CcmExec.exe (Microsoft-signed, runs as SYSTEM under services.exe) runs encoded PowerShell for inventory and compliance baselines on all managed endpoints. Approved scripts read system state only (installed software, hotfixes, service status) and make no network connections. A CcmExec.exe in any other folder, unsigned, or running under a user account is NOT the SCCM client and must be treated as malware masquerading as SCCM.

## INTUNE-03: Intune Defender exclusions
The Intune agent C:\Program Files (x86)\Microsoft Intune Management Extension\AgentExecutor.exe (Microsoft-signed, SYSTEM) may add Microsoft Defender exclusions only for these approved line-of-business folders: Epic Hyperspace, SAP FrontEnd, Revit 2025, QuickBooks. Exclusions for ProgramData, Users\Public, AppData, Temp, or whole drives are never approved. Defender real-time protection is never disabled by policy.

## ADM-02: PsExec and remote administration
PsExec is approved only when run from the JMP-ADM jump servers, by adm- accounts, from C:\Tools\Sysinternals, during an approved change listed in change_calendar.md. PsExec run from a workstation, from a Downloads or Temp folder, or by a standard user account is not approved.

## BKP-01: Offsite backup with rclone
rclone in C:\Program Files\rclone, run by svc_backup from the Nightly-Offsite-Backup scheduled task on SRV-BKP servers, is approved ONLY for the remote corp-s3:corp-backups-prod (a company-owned S3 bucket). svc_backup is denied interactive logon by policy. Any other rclone remote (mega, pcloud, dropbox, personal S3) is data exfiltration.

## RAT-01: Remote support tools
TeamViewer Corporate 15, deployed by SCCM, is the only approved remote support tool, and only on IT Helpdesk hosts (WS-IT-*). AnyDesk, ScreenConnect, RustDesk, and user-installed TeamViewer are prohibited on all other hosts.

## HD-04: Helpdesk account lookups
Helpdesk adm- accounts may run single-account lookups (net user <name> /domain) from WS-IT hosts while working a ticket. Bulk enumeration of groups, trusts, or domain controllers is not part of helpdesk work.

## SW-02: Vendor updaters and autostart
Vendor auto-updaters for Google, Adobe, and Microsoft Edge, and per-user autostart entries for Teams, OneDrive, and Zoom are approved. All of these binaries are vendor-signed; an unsigned binary using one of these names is not covered.

## DEV-05: Developer bootstrap scripts
Engineering may run bootstrap scripts only from the github.com/corp-eng organization. Scripts from personal or third-party GitHub accounts require a security review before execution.

## VPN-02: VPN clients
GlobalProtect is the only approved VPN client. Consumer VPNs are prohibited.
