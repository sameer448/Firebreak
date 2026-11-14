"""Action plane: connectors that touch (or would touch) real systems.

Each actuator has one `execute(action)` method and returns a one-line description of what it did.
Agents never call these: the orchestrator does, and only for automatic actions or actions a
human approved. Which actuator handles each channel is set per org in org.json:

  "actuators": {
    "chat":  {"type": "slack_webhook", "url_env": "SLACK_WEBHOOK_URL"},
    "pager": {"type": "pagerduty", "routing_key_env": "PD_ROUTING_KEY"},
    "case":  {"type": "webhook", "url_env": "CASE_WEBHOOK_URL"}
  }

Types: mock (default: records "would ..." only), slack_webhook, pagerduty (Events API v2),
webhook (POSTs the action as JSON). Secrets come from environment variables, never from the
pack. If a configured variable is missing, the channel falls back to mock and says so.
"""
import json
import os
import urllib.request

from .. import state

CHANNEL_OF = {"create_channel": "chat", "post_summary": "chat", "add_stakeholder": "chat",
              "notify_external": "chat", "page_oncall": "pager", "open_case": "case"}
PD_SEVERITY = {"SEV1": "critical", "SEV2": "error", "SEV3": "warning", "SEV4": "info"}


def describe(a):
    t = a["type"]
    if t == "create_channel":
        return "create channel {}".format(a["target"])
    if t in ("add_stakeholder", "notify_external"):
        return "add stakeholder {} to {}".format(a["target"], a["channel"])
    if t == "page_oncall":
        return "page on-call = {} ({})".format(a["target"], a["payload"][:80])
    if t == "open_case":
        return "open case {} ({})".format(a["target"], a["payload"])
    return "post to {}: {}".format(a["target"], (a.get("payload") or "").splitlines()[0][:80] if a.get("payload") else "")


def _post_json(url, body, timeout=10):
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


class Actuator:
    system = "mock"
    live = False

    def send(self, action):
        """Deliver the action to the real system. Mocks deliver nothing."""

    def execute(self, action):
        verb = "did" if self.live else "would"
        try:
            self.send(action)
            message = "{} {}".format(verb, describe(action))
        except Exception as e:  # a failed delivery must be visible, not silent
            message = "FAILED to {} via {}: {}".format(describe(action), self.system, e)
        state.log_action({"ts": state.now(), "system": self.system, "action_id": action["action_id"],
                          "incident_id": action.get("incident_id"), "type": action["type"], "intent": message})
        return message


class MockActuator(Actuator):
    def __init__(self, channel, note=""):
        self.system = "mock-" + channel + (" ({})".format(note) if note else "")


class SlackWebhook(Actuator):
    live = True

    def __init__(self, url):
        self.system, self.url = "slack", url

    def send(self, a):
        _post_json(self.url, {"text": "[{}] {}: {}".format(a.get("incident_id") or "-", a["type"],
                                                           describe(a))})


class PagerDuty(Actuator):
    live = True
    URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key):
        self.system, self.key = "pagerduty", routing_key

    def send(self, a):
        sev = (a.get("payload") or "")[1:5]
        _post_json(self.URL, {"routing_key": self.key, "event_action": "trigger",
                              "dedup_key": a.get("incident_id") or a["action_id"],
                              "payload": {"summary": (a.get("payload") or describe(a))[:1000],
                                          "source": "soc-ir-agent", "severity": PD_SEVERITY.get(sev, "error"),
                                          "custom_details": {"action_id": a["action_id"], "target": a["target"]}}})


class Webhook(Actuator):
    live = True

    def __init__(self, url):
        self.system, self.url = "webhook", url

    def send(self, a):
        _post_json(self.url, {k: a.get(k) for k in ("action_id", "incident_id", "type", "target", "channel",
                                                     "payload", "reason")})


def build(channel, spec):
    """Actuator for one channel from its org.json spec. Missing secrets -> mock, with a note."""
    kind = (spec or {}).get("type", "mock")
    if kind == "mock":
        return MockActuator(channel)
    env = spec.get("url_env") or spec.get("routing_key_env")
    secret = os.environ.get(env or "")
    if not secret:
        return MockActuator(channel, "{} not set".format(env))
    if kind == "slack_webhook":
        return SlackWebhook(secret)
    if kind == "pagerduty":
        return PagerDuty(secret)
    if kind == "webhook":
        return Webhook(secret)
    raise ValueError("Unknown actuator type '{}' for channel {}".format(kind, channel))


def for_org(org):
    """{action type: actuator} for the org's configured channels."""
    channels = {c: build(c, org.actuators.get(c)) for c in ("chat", "pager", "case")}
    return {action: channels[ch] for action, ch in CHANNEL_OF.items()}


def default_actuators():
    from .. import org as orgmod
    return for_org(orgmod.current())
