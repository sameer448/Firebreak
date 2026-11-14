"""Tests for org packs: loading, validation, policy, source mapping, ingestion webhook, actuators.

  python -m unittest discover -s tests -v
"""
import json
import os
import queue
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from capstone import config, org as orgmod, policy, retrieval, state  # noqa: E402,F401
from capstone.connectors import actuators  # noqa: E402
from capstone.connectors.alert_source import from_source, get_path, render_for_model  # noqa: E402
from capstone.guardrails import check  # noqa: E402
from capstone.severity import asset_criticality, score_severity  # noqa: E402
from capstone.validate import errors, validate  # noqa: E402

HVH = os.path.join(ROOT, "orgs", "harbor-valley-health")


def sample(name):
    with open(os.path.join(HVH, "samples", name), encoding="utf-8") as f:
        return json.load(f)


class TestOrgPacks(unittest.TestCase):
    def test_shipped_packs_have_no_errors(self):
        for oid in orgmod.available():
            o = orgmod.Org(orgmod.org_path(oid))
            self.assertEqual(errors(validate(o)), [], oid)

    def test_template_scaffold_validates(self):
        tmp = tempfile.mkdtemp()
        try:
            dest = os.path.join(tmp, "newco")
            shutil.copytree(config.TEMPLATE_DIR, dest)
            o = orgmod.Org(dest)
            self.assertEqual(errors(validate(o)), [])
            self.assertIn("adm-leaver", o.disabled_accounts())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_orgs_differ(self):
        demo, hvh = orgmod.Org(orgmod.org_path("demo-corp")), orgmod.Org(HVH)
        self.assertNotEqual(demo.disposition["close_threshold"], hvh.disposition["close_threshold"])
        self.assertIn("adm-hschmidt", demo.disabled_accounts())
        self.assertIn("priv-lchen", hvh.disabled_accounts())
        self.assertEqual(set(hvh.sources()), {"sentinel", "falcon"})

    def test_asset_rules_per_org(self):
        hvh = orgmod.Org(HVH)
        self.assertEqual(asset_criticality({"host": "HV-EHR-02", "device_group": "EHR Servers"}, hvh)[0], "critical")
        self.assertEqual(asset_criticality({"host": "HV-NS-1", "device_group": "Clinical Nurse Stations"}, hvh)[0], "high")
        self.assertEqual(asset_criticality({"host": "X", "device_group": "Training Laptops"}, hvh)[0], "low")

    def test_severity_levels_per_org(self):
        hvh, demo = orgmod.Org(HVH), orgmod.Org(orgmod.org_path("demo-corp"))
        # score 4: SEV3 at Demo Corp (needs 5 for SEV2), SEV2 at Harbor Valley (needs 4)
        self.assertEqual(score_severity("medium", "exposed", "single_host", org=demo)["severity"], "SEV3")
        self.assertEqual(score_severity("medium", "exposed", "single_host", org=hvh)["severity"], "SEV2")


class TestPolicy(unittest.TestCase):
    def test_cannot_auto_page(self):
        bad = [{"id": "p", "action": "page_oncall", "target": "x", "mode": "auto", "when": {"always": True}}]
        self.assertTrue(any(lvl == "error" and "always human-gated" in m for lvl, m in policy.validate(bad)))
        # and even if loaded anyway, planning still gates it
        plan = policy.plan(bad, {"incident_id": "inc-1", "severity": "SEV1", "hosts": []}, {})
        self.assertTrue(plan[0]["gated"])

    def test_internal_action_can_be_made_gated(self):
        rules = [{"id": "c", "action": "open_case", "mode": "gated", "when": {"always": True}}]
        self.assertTrue(policy.plan(rules, {"incident_id": "i", "severity": "SEV4", "hosts": []}, {})[0]["gated"])

    def test_unknown_condition_and_signal_rejected(self):
        probs = policy.validate([{"id": "x", "action": "open_case", "when": {"on_tuesdays": True}},
                                 {"id": "y", "action": "open_case", "when": {"signals_any": ["aliens"]}}])
        self.assertEqual(sum(lvl == "error" for lvl, _ in probs), 2)

    def test_hvh_sev1_ransomware_plan(self):
        hvh = orgmod.Org(HVH)
        inc = {"incident_id": "inc-1", "severity": "SEV1", "hosts": ["HV-EHR-02"], "attack_techniques": ["T1490"]}
        plan = policy.plan(hvh.policy, inc, {"destructive": True})
        targets = {p["target"]: p["gated"] for p in plan}
        self.assertTrue(targets["Chief Medical Officer"])
        self.assertTrue(targets["State health department liaison"])
        self.assertTrue(targets["Clinical systems on-call (biomed-ehr)"])
        self.assertFalse(targets["inc-1"])                       # open_case is automatic
        self.assertNotIn("HIPAA Privacy Officer", targets)        # no exfiltration signal

    def test_conditions(self):
        inc = {"incident_id": "i", "severity": "SEV2", "hosts": ["DC-01"], "attack_techniques": ["T1003.001"]}
        self.assertTrue(policy.matches({"techniques_any": ["T1003"]}, inc, {}))
        self.assertTrue(policy.matches({"host_prefix_any": ["dc-"]}, inc, {}))
        self.assertFalse(policy.matches({"severity_at_most": "SEV1"}, inc, {}))
        self.assertTrue(policy.matches({"severity_at_least": "SEV2", "severity_at_most": "SEV3"}, inc, {}))


class TestSourceMapping(unittest.TestCase):
    def setUp(self):
        self.hvh = orgmod.Org(HVH)

    def test_get_path(self):
        obj = {"a": {"b": [{"c": 1}, {"c": 2}]}}
        self.assertEqual(get_path(obj, "a.b[1].c"), 2)
        self.assertIsNone(get_path(obj, "a.b[5].c"))
        self.assertIsNone(get_path(obj, "a.x.c"))

    def test_falcon_mapping(self):
        a = from_source(sample("falcon_disabled_account_lsass.json"), "falcon", self.hvh.sources()["falcon"])
        self.assertEqual(a["host"], "HV-NS-3E-07")
        self.assertEqual(a["device_group"], "Clinical Nurse Stations")
        self.assertIn("powershell.exe", a["process_tree"])
        self.assertTrue(a["raw"].startswith("EDR ALERT\nDetection: Suspicious access to LSASS"))
        self.assertIn("Host: HV-NS-3E-07 (Device group: Clinical Nurse Stations", a["raw"])
        self.assertEqual(a["vendor_alert_id"], "ldt:hvh0000000000000000000000000000:4402")

    def test_sentinel_mapping_and_guardrails(self):
        a = from_source(sample("sentinel_ransomware_ehr.json"), "sentinel", self.hvh.sources()["sentinel"])
        self.assertEqual(a["user"], "HVH\\priv-xadmin")
        self.assertEqual(a["host"], "HV-EHR-02")
        rules = {g["rule"] for g in check(a, self.hvh)}
        self.assertIn("unlisted_admin", rules)               # priv- prefix, not on HVH roster

    def test_same_vendor_id_same_alert_id(self):
        m = self.hvh.sources()["falcon"]
        p = sample("falcon_phi_exfil_pacs.json")
        p2 = dict(p, created_timestamp="2030-01-01T00:00:00Z")
        self.assertEqual(from_source(p, "falcon", m)["alert_id"], from_source(p2, "falcon", m)["alert_id"])

    def test_render_matches_training_layout(self):
        text = render_for_model({"detection": "D", "host": "H", "device_group": "G", "os": "O", "user": "U"})
        self.assertEqual(text, "EDR ALERT\nDetection: D\nHost: H (Device group: G, OS: O)\nUser: U")


class TestActuators(unittest.TestCase):
    def test_missing_secret_falls_back_to_mock(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NOPE_URL", None)
            a = actuators.build("chat", {"type": "slack_webhook", "url_env": "NOPE_URL"})
        self.assertIsInstance(a, actuators.MockActuator)
        self.assertIn("NOPE_URL not set", a.system)

    def test_pagerduty_payload(self):
        sent = {}
        with mock.patch.object(actuators, "_post_json", lambda url, body: sent.update(url=url, body=body)), \
                mock.patch.object(actuators.state, "log_action", lambda e: None):
            pd = actuators.PagerDuty("rk-123")
            msg = pd.execute({"action_id": "act-1", "incident_id": "inc-1", "type": "page_oncall",
                              "target": "IR", "channel": "#inc-1", "payload": "[SEV1] T1490 on HV-EHR-02"})
        self.assertTrue(msg.startswith("did page on-call"))
        self.assertEqual(sent["body"]["routing_key"], "rk-123")
        self.assertEqual(sent["body"]["payload"]["severity"], "critical")
        self.assertEqual(sent["body"]["dedup_key"], "inc-1")

    def test_delivery_failure_is_visible(self):
        def boom(url, body):
            raise OSError("connection refused")
        with mock.patch.object(actuators, "_post_json", boom), mock.patch.object(actuators.state, "log_action", lambda e: None):
            msg = actuators.SlackWebhook("http://x").execute(
                {"action_id": "a", "type": "create_channel", "target": "#inc-1", "channel": "#inc-1"})
        self.assertTrue(msg.startswith("FAILED"))


class TestIngestWebhook(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from capstone.web import server
        self.server = server
        self.tmp, self.saved_state, self.saved_org = tempfile.mkdtemp(), config.STATE_DIR, server.ORG
        config.STATE_DIR = self.tmp
        server.ORG = orgmod.Org(HVH)
        self.saved_queue, server.QUEUE = server.QUEUE, queue.Queue()   # keep jobs away from the real worker
        self.client = TestClient(server.app)
        self.h = {"X-API-Key": server.INGEST_KEY}

    def tearDown(self):
        config.STATE_DIR, self.server.ORG, self.server.QUEUE = self.saved_state, self.saved_org, self.saved_queue
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_auth_required(self):
        self.assertEqual(self.client.post("/api/ingest/falcon", json={}).status_code, 401)
        self.assertEqual(self.client.post("/api/ingest/falcon", json={}, headers={"X-API-Key": "wrong"}).status_code, 401)

    def test_ingest_and_dedup(self):
        p = sample("falcon_disabled_account_lsass.json")
        r = self.client.post("/api/ingest/falcon", json=p, headers=self.h)
        self.assertEqual(r.status_code, 202)
        self.assertEqual(r.json()["results"][0]["status"], "queued")
        r2 = self.client.post("/api/ingest/falcon", json=p, headers=self.h)
        self.assertEqual(r2.json()["results"][0]["status"], "duplicate")
        self.assertEqual(r2.json()["accepted"], 0)

    def test_batch_and_bad_payloads(self):
        batch = [sample("falcon_phi_exfil_pacs.json"), sample("falcon_disabled_account_lsass.json")]
        self.assertEqual(self.client.post("/api/ingest/falcon", json=batch, headers=self.h).json()["accepted"], 2)
        self.assertEqual(self.client.post("/api/ingest/nosuch", json={}, headers=self.h).status_code, 400)
        r = self.client.post("/api/ingest/falcon", json={"detection_id": "x"}, headers=self.h)
        self.assertEqual(r.status_code, 400)
        self.assertIn("missing required fields", r.json()["detail"])

    def test_org_endpoint(self):
        o = self.client.get("/api/org").json()
        self.assertEqual(o["id"], "harbor-valley-health")
        self.assertEqual(o["ingest"]["sources"], ["falcon", "sentinel"])
        self.assertFalse(any(v["level"] == "error" for v in o["validation"]))


if __name__ == "__main__":
    unittest.main()
