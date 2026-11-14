"""Engine-level settings. Everything organization-specific (thresholds, assets, identity, severity
levels, escalation policy, sources, actuators, knowledge) lives in an org pack under orgs/<id>/
and is loaded by capstone/org.py.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORGS_DIR = os.path.join(ROOT, "orgs")
TEMPLATE_DIR = os.path.join(ROOT, "capstone", "templates", "org")
DEFAULT_ORG = os.environ.get("SOC_ORG", "demo-corp")

TRIAGE_MODEL = "soc-triage"      # fine-tuned Llama 3.2 3B: verdict, ATT&CK, evidence
IR_MODEL = "llama3.1:8b"         # larger general model: structured fact extraction for IR

# Set by org.activate(); kept as module attributes so tests can point them at temp folders.
STATE_DIR = os.path.join(ROOT, "runs", DEFAULT_ORG)
TRIAGE_INDEX = os.path.join(ORGS_DIR, DEFAULT_ORG, ".index", "triage")
IR_INDEX = os.path.join(ORGS_DIR, DEFAULT_ORG, ".index", "ir")
