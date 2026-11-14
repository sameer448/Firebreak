import json, re, collections, ntpath, os

D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
train = [json.loads(l) for l in open(os.path.join(D, "train.jsonl"), encoding="utf-8")]
test = [json.loads(l) for l in open(os.path.join(D, "test.jsonl"), encoding="utf-8")]


def fields(r):
    u = r["conversations"][1]["content"]
    if "EDR ALERT (JSON)" in u:
        j = json.loads(u.split("EDR ALERT (JSON)\n", 1)[1])
        return dict(title=j["detection_name"], sev=j["severity"], time=j["timestamp"],
                    group=j["device"]["device_group"], host=j["device"]["hostname"], user=j["user"],
                    proc=j["process"]["image"], cmd=j["process"]["command_line"],
                    tree=j["process"]["ancestry"], signer=j["process"]["signature"], extra=j["context"])
    g = lambda k: re.search(k + r": (.*)", u).group(1)
    host = re.match(r"(\S+) \(Device group: (.*?), OS", g("Host"))
    return dict(title=g("Detection"), sev=g("Vendor severity"), time=g("Timestamp"),
                group=host.group(2), host=host.group(1), user=g("User"), proc=g("Process"),
                cmd=g("Command line"), tree=g("Process tree"), signer=g("Signature"),
                extra=g("Additional context"))


def user_type(u):
    if "SYSTEM" in u or "APPPOOL" in u:
        return "system"
    if "\\adm-" in u:
        return "admin"
    if "\\svc_" in u:
        return "service"
    return "standard"


def hour_bucket(t):
    h = int(t[11:13])
    return "offhours" if (h < 7 or h > 19) else "business"


def server(group):
    return "workstation" if "Workstation" in group else "server"


def predictability(name, fn, rows=train):
    by = collections.defaultdict(collections.Counter)
    for r in rows:
        by[fn(fields(r))][r["meta"]["verdict"]] += 1
    acc = sum(max(c.values()) for c in by.values()) / len(rows)
    return acc, by


print("== Single-feature shortcuts (majority-verdict accuracy; chance ~49%) ==")
checks = [
    ("vendor severity", lambda f: f["sev"]),
    ("detection title", lambda f: f["title"]),
    ("signer", lambda f: f["signer"]),
    ("user type", lambda f: user_type(f["user"])),
    ("off-hours vs business", lambda f: hour_bucket(f["time"])),
    ("workstation vs server", lambda f: server(f["group"])),
    ("user type + host type", lambda f: (user_type(f["user"]), server(f["group"]))),
    ("vendor sev + user type", lambda f: (f["sev"], user_type(f["user"]))),
]
for name, fn in checks:
    acc, by = predictability(name, fn)
    print("  {:<28} {:.0%}".format(name, acc))
    if name in ("vendor severity", "user type", "off-hours vs business", "signer"):
        for k, c in sorted(by.items(), key=lambda x: -sum(x[1].values()))[:6]:
            print("      {:<55} {}".format(str(k)[:55], dict(c)))

print("\n== Giveaway phrases in 'Additional context' ==")
phrases = ["0 prevalence", "unsigned", "Software Center", "maintenance window", "change window",
           "ransom", "policy", "ticket", "external sender", "VirusTotal", "self-signed",
           "scheduled", "earlier", "no network", "No network"]
for p in phrases:
    c = collections.Counter(r["meta"]["verdict"] for r in train if p.lower() in fields(r)["extra"].lower())
    if c:
        print("  {:<20} {}".format(p, dict(c)))

print("\n== Answer diversity ==")
summ = collections.defaultdict(set)
ev = collections.defaultdict(set)
for r in train:
    a = r["conversations"][2]["content"]
    s = re.search(r"Summary: (.*)", a).group(1)
    summ[r["meta"]["scenario"]].add(re.sub(r"\d+", "N", s))
print("  distinct summary templates across all scenarios: {}".format(sum(len(v) for v in summ.values())))
print("  scenarios with exactly 1 summary wording: {}/{}".format(sum(1 for v in summ.values() if len(v) == 1), len(summ)))
conf = collections.Counter((r["meta"]["verdict"], re.search(r"Confidence: (\w+)", r["conversations"][2]["content"]).group(1)) for r in train)
print("  verdict x confidence:", dict(conf))
sevmap = collections.Counter((r["meta"]["scenario"], re.search(r"Severity: (\w+)", r["conversations"][2]["content"]).group(1)) for r in train)
print("  scenarios with more than one output severity:", len({s for s, _ in sevmap}) - len({s for s, _ in sevmap} ) + sum(1 for s in {x for x, _ in sevmap} if len([1 for (a, b) in sevmap if a == s]) > 1))

print("\n== Length (chars; ~3.5 chars/token) ==")
lens = sorted(sum(len(m["content"]) for m in r["conversations"]) for r in train)
print("  min {} median {} max {}  -> max ~{} tokens".format(lens[0], lens[len(lens) // 2], lens[-1], lens[-1] // 3))

print("\n== Train/test overlap ==")
def skeleton(r):
    f = fields(r)
    s = f["cmd"]
    s = re.sub(r"[0-9a-f]{64}", "", s)
    s = re.sub(r"\d+", "N", s)
    s = re.sub(r"\\Users\\[^\\]+", r"\\Users\\U", s)
    return r["meta"]["scenario"], re.sub(r"[a-z]{4,8}\.(exe|dll|bin|b64|aspx|txt)", "R.\\1", s)
tr = set(skeleton(r) for r in train)
print("  test alerts whose command-line skeleton also appears in train: {}/{}".format(sum(1 for r in test if skeleton(r) in tr), len(test)))
print("  scenarios in test that are absent from train: {}".format({r["meta"]["scenario"] for r in test} - {r["meta"]["scenario"] for r in train}))

print("\n== Prompt variety ==")
print("  distinct user-message openers:", len({r["conversations"][1]["content"].split("\n")[0] for r in train}))
print("  examples containing retrieved context / Source line:", sum(1 for r in train if "Sources:" in r["conversations"][2]["content"]))
print("  OS coverage:", collections.Counter("Windows" in fields(r)["group"] or "Windows" for r in train).most_common(1))
print("  alerts with more than one correlated event in context:", sum(1 for r in train if "Within" in fields(r)["extra"]))


print("\n== Parent-process shortcuts (v2 checks) ==")
def parent_name(f):
    first = f["tree"].split(" <- ")[0]
    first = re.split(r"\.exe", first, flags=re.I)[0] + ".exe"
    return ntpath.basename(first).lower()
def parent_path(f):
    first = f["tree"].split(" <- ")[0]
    return re.split(r"\.exe", first, flags=re.I)[0].lower() + ".exe"
for name, fn in (("immediate parent name", parent_name),
                 ("parent name + process name", lambda f: (parent_name(f), ntpath.basename(f["proc"]).lower())),
                 ("process name alone", lambda f: ntpath.basename(f["proc"]).lower())):
    acc, _ = predictability(name, fn)
    print("  {:<28} {:.0%}".format(name, acc))
full = sum(1 for r in train if all(":\\" in p or p.startswith("\\") for p in fields(r)["tree"].split(" <- ")))
print("  alerts with full paths for every ancestor: {}/{}".format(full, len(train)))

print("\n== Masquerade coverage ==")
for nm in ("ccmexec.exe", "werfault.exe", "agentexecutor.exe", "onedrive.exe"):
    c = collections.Counter()
    for r in train:
        f = fields(r)
        if nm in (parent_name(f), ntpath.basename(f["proc"]).lower()):
            c[r["meta"]["verdict"]] += 1
    print("  {:<20} {}".format(nm, dict(c)))

print("\n== Retrieved-context examples ==")
rag = [r for r in train if r["meta"].get("rag")]
print("  with context: {}  answers with Sources line: {}".format(len(rag), sum(1 for r in rag if "Sources:" in r["conversations"][2]["content"])))
print("  non-context answers with a Sources line (should be 0):", sum(1 for r in train if not r["meta"].get("rag") and "Sources:" in r["conversations"][2]["content"]))
bad = 0
for r in rag:
    u = r["conversations"][1]["content"]; a = r["conversations"][2]["content"]
    cited = [s.strip() for s in a.split("Sources:")[1].split(",")]
    bad += any("[" + s + "]" not in u for s in cited)
print("  answers citing a document not present in the context (should be 0):", bad)
print("  verdicts among context examples:", dict(collections.Counter(r["meta"]["verdict"] for r in rag)))

hold_path = os.path.join(D, "test_holdout.jsonl")
if os.path.exists(hold_path):
    hold = [json.loads(l) for l in open(hold_path, encoding="utf-8")]
    print("\n== Holdout ==")
    print("  holdout scenarios:", sorted({r["meta"]["scenario"] for r in hold}))
    print("  holdout scenarios also in train (should be empty):", {r["meta"]["scenario"] for r in hold} & {r["meta"]["scenario"] for r in train})
