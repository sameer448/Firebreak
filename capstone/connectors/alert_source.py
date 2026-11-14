"""Input connector: EDR alert (key/value text or JSON) -> canonical alert dict.

Every downstream agent works on the canonical fields, so adding a new EDR/SIEM source means
writing one more normalizer here, not touching the agents. The original alert text is kept
verbatim in `raw` because that is what the fine-tuned triage model was trained on.
"""
import hashlib
import json
import re

KV_FIELDS = {
    "detection": "detection", "vendor severity": "vendor_severity", "timestamp": "timestamp",
    "user": "user", "process": "process_image", "command line": "command_line",
    "process tree": "process_tree", "signature": "signature", "prevalence": "prevalence",
    "sha256": "sha256", "network": "network", "additional context": "context",
}


def extract_alert_text(text):
    """Strip any instruction prefix or pre-retrieved context; keep from 'EDR ALERT' on."""
    i = text.find("EDR ALERT")
    return (text[i:] if i >= 0 else text).strip()


def _from_kv(body):
    out = {}
    for line in body.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip().lower(), value.strip()
        if key == "host":
            m = re.match(r"(\S+)\s*\(Device group:\s*([^,]+),\s*OS:\s*([^)]+)\)", value)
            if m:
                out["host"], out["device_group"], out["os"] = (g.strip() for g in m.groups())
            else:
                out["host"] = value
        elif key in KV_FIELDS:
            out[KV_FIELDS[key]] = value
    return out


def _from_json(body):
    data = json.loads(body[body.index("{"):body.rindex("}") + 1])
    device, proc = data.get("device", {}), data.get("process", {})
    return {
        "detection": data.get("detection_name", ""), "vendor_severity": data.get("severity", ""),
        "timestamp": data.get("timestamp", ""), "host": device.get("hostname", ""),
        "device_group": device.get("device_group", ""), "os": device.get("os", ""),
        "user": data.get("user", ""), "process_image": proc.get("image", ""),
        "command_line": proc.get("command_line", ""), "process_tree": proc.get("ancestry", ""),
        "signature": proc.get("signature", ""), "prevalence": proc.get("prevalence", ""),
        "sha256": proc.get("sha256", ""), "network": data.get("network", ""),
        "context": data.get("context", ""),
    }


CANONICAL = ("detection", "vendor_severity", "timestamp", "host", "device_group", "os", "user", "process_image",
             "command_line", "process_tree", "signature", "prevalence", "sha256", "network", "context")
REQUIRED = ("detection", "host", "timestamp")


def normalize(text, source="edr-text"):
    """Canonical alert from the built-in EDR text/JSON layouts (what the triage model was trained on)."""
    body = extract_alert_text(text.replace("\r\n", "\n"))
    is_json = body.startswith("EDR ALERT (JSON)")
    fields = _from_json(body) if is_json else _from_kv(body)
    alert = {k: "" for k in CANONICAL}
    alert.update({k: v for k, v in fields.items() if v})
    alert["alert_id"] = "alt-" + hashlib.sha256(body.encode("utf-8")).hexdigest()[:10]
    alert["source"] = source
    alert["format"] = "json" if is_json else "kv"
    alert["raw"] = body
    return alert


# ---------------------------------------------------------------- mapped sources (any vendor JSON)

def get_path(obj, path):
    """Dot path with list indexes: 'properties.entities[0].hostName'. Missing -> None."""
    for part in re.findall(r"[^.\[\]]+|\[\d+\]", path):
        if part.startswith("["):
            idx = int(part[1:-1])
            obj = obj[idx] if isinstance(obj, list) and -len(obj) <= idx < len(obj) else None
        else:
            obj = obj.get(part) if isinstance(obj, dict) else None
        if obj is None:
            return None
    return obj


def _as_text(value, field):
    if value is None:
        return ""
    if isinstance(value, list):
        sep = " <- " if field == "process_tree" else "; "
        return sep.join(_as_text(v, field) for v in value if v not in (None, ""))
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value).strip()


def map_payload(payload, mapping):
    """Canonical alert from a vendor JSON payload using a sources/<name>.json mapping.

    mapping["fields"][canonical] is a dot path, or a list of paths (first non-empty wins).
    mapping["constants"] fills fields the source never sends (e.g. a fixed device_group).
    """
    alert = {k: "" for k in CANONICAL}
    for field, paths in mapping.get("fields", {}).items():
        if field not in alert:
            continue
        for p in paths if isinstance(paths, list) else [paths]:
            value = _as_text(get_path(payload, p), field)
            if value:
                alert[field] = value
                break
    for field, value in mapping.get("constants", {}).items():
        if field in alert and not alert[field]:
            alert[field] = str(value)
    vendor_id = _as_text(get_path(payload, mapping["id_field"]), "id") if mapping.get("id_field") else ""
    body = render_for_model(alert)
    alert["alert_id"] = "alt-" + hashlib.sha256(
        (vendor_id or json.dumps(payload, sort_keys=True)).encode("utf-8")).hexdigest()[:10]
    alert["vendor_alert_id"] = vendor_id
    alert["source"] = mapping.get("name", "mapped")
    alert["format"] = "mapped"
    alert["raw"] = body
    return alert


def render_for_model(alert):
    """Rebuild a canonical alert in the key/value layout the fine-tuned model was trained on, so
    alerts from any vendor reach the model in the format it knows."""
    host = alert.get("host", "")
    if alert.get("device_group") or alert.get("os"):
        host = "{} (Device group: {}, OS: {})".format(host, alert.get("device_group") or "unknown",
                                                      alert.get("os") or "unknown")
    lines = [("Detection", alert.get("detection")), ("Vendor severity", alert.get("vendor_severity")),
             ("Timestamp", alert.get("timestamp")), ("Host", host), ("User", alert.get("user")),
             ("Process", alert.get("process_image")), ("Command line", alert.get("command_line")),
             ("Process tree", alert.get("process_tree")), ("Signature", alert.get("signature")),
             ("Prevalence", alert.get("prevalence")), ("SHA256", alert.get("sha256")),
             ("Network", alert.get("network")), ("Additional context", alert.get("context"))]
    return "EDR ALERT\n" + "\n".join("{}: {}".format(k, v) for k, v in lines if v)


def from_source(data, source, mapping=None):
    """One entry point for every source: text for builtin-edr-text, dict for mapped JSON sources."""
    if mapping is None or mapping.get("type") == "builtin-edr-text":
        return normalize(data if isinstance(data, str) else json.dumps(data), source=source)
    payload = json.loads(data) if isinstance(data, str) else data
    return map_payload(payload, mapping)


def missing_required(alert):
    return [f for f in REQUIRED if not alert.get(f)]
