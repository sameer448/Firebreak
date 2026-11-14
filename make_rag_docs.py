"""Writes the incident-response playbooks into rag_docs/.
Steps and IDs match the playbook text used in the training examples, so the
fine-tuned model can cite them exactly. Policy documents (allowlist, roster,
false positives, change calendar) are hand-written files in rag_docs/."""
import os
from generate_dataset import PLAYBOOKS

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rag_docs")

EXTRA = {
    "cred": ("Credential dumping (T1003), LSASS access by non-system tools, comsvcs.dll MiniDump, "
             "and Kerberoasting (T1558.003: bursts of RC4 service-ticket requests, tools such as Rubeus).",
             "Kerberoasting: identify every service account whose ticket was requested, rotate those passwords to 25+ "
             "characters, and move service accounts to gMSA where possible."),
    "phish": ("Macro documents spawning shells or script hosts, malicious attachments, links to newly registered domains.",
              "Notify the user's manager and remind the user how to report phishing."),
    "malexec": ("Unknown or unsigned binaries executing, LOLBin downloads (certutil, bitsadmin), Run keys, scheduled tasks, "
                "masquerading binaries using trusted names in the wrong path.",
                "Masquerading: hunt fleet-wide for the trusted file name running outside its legitimate folder."),
    "lateral": ("PsExec-style remote service creation, admin-share access, burst domain reconnaissance, "
                "use of disabled or offboarded accounts.",
                "Disabled or offboarded accounts showing activity: treat as credential compromise and reset krbtgt if the account was privileged."),
    "ransom": ("Shadow copy deletion, backup catalog deletion, mass file renames with new extensions, ransom notes.",
               "Do not contact or pay the threat actor; all communication goes through legal and the insurance carrier."),
    "exfil": ("Cloud sync tools uploading to unapproved remotes, large outbound transfers, archive staging.",
              "Preserve tool configs and logs (for rclone: the config file and --log-file output) before cleanup."),
    "web": ("w3wp.exe or other web server processes spawning shells, new web pages outside deployments.",
            "Check every web server for similar new files in the web root."),
    "evasion": ("Defender real-time protection disabled, broad exclusions added, tampering with security tools.",
                "Exclusions added by anything other than the Intune AgentExecutor in Program Files (x86) are unauthorized."),
    "rat": ("AnyDesk, ScreenConnect, RustDesk, or user-installed TeamViewer on non-helpdesk hosts; help-desk impersonation calls.",
            "Warn all staff about the fake IT-support calls through the security awareness channel."),
}

for key, (doc, pid, text, _action) in PLAYBOOKS.items():
    title, _, rest = text.partition(". ")
    steps = [s.strip() for s in rest.split(") ") if s.strip()]
    lines = ["# {} {}".format(pid, title), "",
             "Owner: Incident Response. Severity guidance and steps below are mandatory for this alert category.", "",
             "## Applies to", EXTRA[key][0], "", "## Response steps"]
    sla = ""
    for s in steps:
        s = s.rstrip(" 1234567890")
        if s.startswith("SLA:") or " SLA:" in s:
            body, _, sla = s.partition("SLA:")
            s = body.strip()
        if s and not s.startswith("Applies to"):
            lines.append("- " + s.rstrip(". ") + ".")
    if sla:
        lines += ["", "## SLA", sla.strip()]
    lines += ["", "## Additional guidance", EXTRA[key][1], ""]
    with open(os.path.join(OUT, doc), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("wrote", doc)

with open(os.path.join(OUT, "playbook_insider_threat.md"), "w", encoding="utf-8") as f:
    f.write("# PB-INS-01 Insider Threat\n\nOwner: Incident Response with HR and Legal.\n\n## Applies to\n"
            "Suspected misuse of access by a current employee or contractor.\n\n## Response steps\n"
            "- Coordinate with HR and legal before contacting the employee.\n"
            "- Preserve mailbox and endpoint data under legal hold.\n"
            "- Restrict access quietly; do not alert the subject.\n")
print("wrote playbook_insider_threat.md")
