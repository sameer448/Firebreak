"""API tests for the web console, against a temporary state directory (no Ollama needed).

  python -m unittest discover -s tests -v
"""
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from capstone import config, retrieval, state  # noqa: E402,F401  (retrieval puts .rag_libs on sys.path)
from fastapi.testclient import TestClient  # noqa: E402
from capstone.web.server import app  # noqa: E402


class TestConsoleAPI(unittest.TestCase):
    def setUp(self):
        self.tmp, self.saved = tempfile.mkdtemp(), config.STATE_DIR
        config.STATE_DIR = self.tmp
        self.client = TestClient(app)
        state.save_incident({
            "incident_id": "inc-t-0001", "escalation_id": "esc-t-0001", "opened_at": "2026-01-01T00:00:00Z",
            "severity": "SEV1", "severity_detail": {"score": 6, "breakdown": {}, "reasons": ["test"]},
            "facts": {"incident_summary": "<script>alert(1)</script>"}, "playbook_id": "PB-RANS-01",
            "hosts": ["SRV-FILE01"], "attack_techniques": ["T1490"], "sources": [], "sla": "",
            "actions": [{"action_id": "act-t-0001", "type": "page_oncall", "target": "Alice", "gated": True,
                         "reason": "SEV1"}]})
        state.queue_approval({"action_id": "act-t-0001", "incident_id": "inc-t-0001", "type": "page_oncall",
                              "target": "Alice", "channel": "#inc-t-0001", "payload": "x", "gated": True,
                              "reason": "SEV1"})

    def tearDown(self):
        config.STATE_DIR = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pages_and_lists(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/api/stats").json()["pending_approvals"], 1)
        self.assertEqual(self.client.get("/api/incidents").json()[0]["pending_approvals"], 1)
        self.assertEqual(len(self.client.get("/api/demo-alerts").json()), 9)

    def test_incident_detail_has_live_action_status(self):
        inc = self.client.get("/api/incidents/inc-t-0001").json()
        self.assertEqual(inc["actions"][0]["status"], "pending")
        self.assertEqual(self.client.get("/api/incidents/nope").status_code, 404)

    def test_approval_gate(self):
        self.assertEqual(self.client.post("/api/approvals/act-t-0001/approve", json={"by": ""}).status_code, 422)
        r = self.client.post("/api/approvals/act-t-0001/approve", json={"by": "Tester", "note": "ok"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["intent"].startswith("would page on-call"))
        self.assertEqual(self.client.post("/api/approvals/act-t-0001/deny", json={"by": "Tester"}).status_code, 409)
        self.assertEqual(self.client.post("/api/approvals/act-x/approve", json={"by": "T"}).status_code, 404)
        inc = self.client.get("/api/incidents/inc-t-0001").json()
        self.assertEqual(inc["actions"][0]["status"], "approved")
        self.assertEqual(inc["actions"][0]["by"], "Tester")
        events = [e["event"] for e in self.client.get("/api/audit").json()]
        self.assertIn("action_approved", events)

    def test_submit_validation(self):
        self.assertEqual(self.client.post("/api/alerts", json={"text": "   "}).status_code, 400)
        self.assertEqual(self.client.post("/api/alerts", json={"text": "x" * 20001}).status_code, 400)

    def test_untrusted_text_returned_as_data(self):
        # The API returns raw strings; the console escapes them (esc() in app.js). Verify no server-side mangling.
        inc = self.client.get("/api/incidents/inc-t-0001").json()
        self.assertEqual(inc["facts"]["incident_summary"], "<script>alert(1)</script>")


if __name__ == "__main__":
    unittest.main()
