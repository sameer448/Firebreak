"""Firebreak: agentic CSOC -> IR pipeline. Every command works on one org pack (default: $SOC_ORG or demo-corp).

Setup check
  python -m capstone doctor                            Python, packages, Ollama, models, org pack, indexes

Org packs
  python -m capstone org list                          available org packs
  python -m capstone org init acme                     scaffold orgs/acme/ from the template
  python -m capstone --org acme org validate           check org.json, playbooks, roster, sources, policy
  python -m capstone --org acme org ingest             build the org's triage + IR vector indexes
  python -m capstone --org acme org show               print the loaded profile

Alerts and incidents
  python -m capstone run data/capstone_demo/*.txt      triage alert files end to end
         [--source edr-text] [--interactive] [--reset] [--close-threshold 0.85]
  python -m capstone --org acme run orgs/acme/samples/sentinel_*.json --source sentinel
  python -m capstone approvals                         gated actions waiting for a human
  python -m capstone approve act-2026-0007 --by "Sameer" [--note "..."]
  python -m capstone deny    act-2026-0007 --by "Sameer" [--note "..."]
  python -m capstone status                            dispositions, incidents, pending approvals
  python -m capstone reset                             clear this org's runs/<org>/ state
"""
import argparse
import glob
import json
import os
import shutil
import sys

from . import config, state
from . import org as orgmod


def load_inputs(path, source, org):
    """A file -> list of (label, data). Mapped sources accept one JSON object or a list of them."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if org.sources().get(source, {}).get("type", "json") == "builtin-edr-text":
        return [(os.path.basename(path), text)]
    data = json.loads(text)
    items = data if isinstance(data, list) else [data]
    return [("{}#{}".format(os.path.basename(path), i + 1) if len(items) > 1 else os.path.basename(path), item)
            for i, item in enumerate(items)]


def cmd_run(args, org):
    from .orchestrator import Pipeline
    if args.reset:
        state.reset()
    paths = [p for pattern in args.alerts for p in sorted(glob.glob(pattern))]
    if not paths:
        sys.exit("No alert files matched.")
    pipe = Pipeline(interactive=args.interactive, close_threshold=args.close_threshold)
    for p in paths:
        for label, data in load_inputs(p, args.source, org):
            try:
                pipe.process_text(data, label=label, source=args.source)
            except ValueError as e:
                print("SKIPPED {}: {}".format(label, e))
    print("-" * 78)
    cmd_status(args)


def cmd_approvals(args):
    pending = [a for a in state.load_approvals().values() if a["status"] == "pending"]
    if not pending:
        print("No actions waiting for approval.")
    for a in pending:
        print("{}  {:<20} {:<40} {}  ({})".format(a["action_id"], a["type"], a["target"],
                                                  a["incident_id"] or a.get("escalation_id"), a["reason"]))


def cmd_status(args):
    counts = {}
    for e in state.load_audit():
        if e["event"] == "disposition":
            counts[e["disposition"]] = counts.get(e["disposition"], 0) + 1
    print("Org: {}   state: {}".format(orgmod.current().id, config.STATE_DIR))
    print("Dispositions: " + (", ".join("{}={}".format(k, v) for k, v in sorted(counts.items())) or "none"))
    for inc in state.load_incidents().values():
        print("{}  {}  hosts={}  techniques={}  {}".format(inc["incident_id"], inc["severity"], ",".join(inc["hosts"]),
                                                          ",".join(inc["attack_techniques"]), inc["playbook_id"]))
    print("Pending approvals: {}".format(sum(a["status"] == "pending" for a in state.load_approvals().values())))


def cmd_org(args, org):
    if args.org_cmd == "list":
        for oid in orgmod.available():
            o = orgmod.Org(orgmod.org_path(oid))
            print("{:<16} {}".format(oid, o.name))
    elif args.org_cmd == "init":
        dest = os.path.join(config.ORGS_DIR, args.new_id)
        if os.path.exists(dest):
            sys.exit("{} already exists".format(dest))
        shutil.copytree(config.TEMPLATE_DIR, dest)
        cfg_path = os.path.join(dest, "org.json")
        with open(cfg_path, encoding="utf-8") as f:
            text = f.read().replace("__ORG_ID__", args.new_id)
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(text)
        print("Created {}\nNext: edit org.json, add playbooks/ knowledge/ sources/, then\n"
              "  python -m capstone --org {} org validate\n  python -m capstone --org {} org ingest".format(
                  dest, args.new_id, args.new_id))
    elif args.org_cmd == "validate":
        from .validate import errors, validate
        findings = validate(org)
        for level, area, msg in findings:
            print("{:<8}{:<11}{}".format(level.upper(), area, msg))
        errs = errors(findings)
        print("\n{}: {} error(s), {} warning(s)".format(org.id, len(errs), sum(f[0] == "warning" for f in findings)))
        sys.exit(1 if errs else 0)
    elif args.org_cmd == "ingest":
        from .retrieval import ingest
        for kind in ("triage", "ir"):
            files, chunks = ingest(kind, org)
            print("{:<7} {} files -> {} chunks -> {}".format(kind, files, chunks, os.path.join(org.index_dir, kind)))
    elif args.org_cmd == "show":
        print(json.dumps(org.summary(), indent=2))


def main():
    ap = argparse.ArgumentParser(prog="python -m capstone", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", default=None, help="org pack id or path (default: $SOC_ORG or demo-corp)")
    sub = ap.add_subparsers(dest="cmd")
    o = sub.add_parser("org")
    osub = o.add_subparsers(dest="org_cmd")
    for name in ("list", "validate", "ingest", "show"):
        osub.add_parser(name)
    init = osub.add_parser("init")
    init.add_argument("new_id")
    r = sub.add_parser("run")
    r.add_argument("alerts", nargs="+")
    r.add_argument("--source", default="edr-text")
    r.add_argument("--interactive", action="store_true")
    r.add_argument("--reset", action="store_true")
    r.add_argument("--close-threshold", type=float, default=None)
    sub.add_parser("approvals")
    for name in ("approve", "deny"):
        p = sub.add_parser(name)
        p.add_argument("action_id")
        p.add_argument("--by", required=True)
        p.add_argument("--note", default="")
    sub.add_parser("status")
    sub.add_parser("reset")
    sub.add_parser("doctor")
    args = ap.parse_args()

    if args.cmd == "doctor":
        from .doctor import run
        sys.exit(0 if run(args.org) else 1)
    if args.cmd == "org" and args.org_cmd in ("list", "init"):
        return cmd_org(args, None)
    try:
        org = orgmod.activate(args.org)
    except orgmod.OrgError as e:
        sys.exit("Cannot load org pack: {}".format(e))

    if args.cmd == "org":
        cmd_org(args, org)
    elif args.cmd == "run":
        cmd_run(args, org)
    elif args.cmd == "approvals":
        cmd_approvals(args)
    elif args.cmd in ("approve", "deny"):
        from .orchestrator import approve, deny
        try:
            (approve if args.cmd == "approve" else deny)(args.action_id, args.by, args.note)
        except KeyError:
            sys.exit("No such action: {} (see: python -m capstone approvals)".format(args.action_id))
        except ValueError as e:
            sys.exit("Not changed: {}".format(e))
    elif args.cmd == "status":
        cmd_status(args)
    elif args.cmd == "reset":
        state.reset()
        print("State cleared for {}.".format(org.id))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
