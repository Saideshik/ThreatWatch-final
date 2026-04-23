"""
ThreatWatch v2 — AI Security Dashboard Backend
- Unique AI analysis per alert
- Action endpoints: escalate / investigate / resolve
- SSE live stream
- /ingest endpoint for Ubuntu forwarder
- In-memory alert storage (ingested alerts persist until restart)
"""

import json
import os
import asyncio
import hashlib
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from openai import OpenAI

# ─── Config ───────────────────────────────────────────────────────────────────
ALERTS_FILE    = os.getenv("ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

app = FastAPI(title="ThreatWatch API", version="2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory stores
alert_actions:    dict[str, str]  = {}
_ai_cache:        dict[str, dict] = {}
ingested_alerts:  list[dict]      = []


# ─── Original Scoring Logic (unchanged) ───────────────────────────────────────
def get_technique_score(desc: str) -> int:
    d = desc.lower()
    if "credential" in d:                  return 9
    if "privilege"  in d:                  return 8
    if "lateral"    in d or "smb" in d:    return 9
    if "persistence" in d:                 return 8
    if "defense evasion" in d:             return 9
    if "powershell" in d:                  return 5
    if "cmd"        in d or "execution" in d: return 5
    if "discovery"  in d:                  return 4
    return 3

def get_asset_value(agent: str) -> int:
    a = agent.lower()
    return 10 if ("server" in a or "dc" in a) else 4

def get_privilege_score(desc: str) -> int:
    d = desc.lower()
    return 9 if ("admin" in d or "administrator" in d) else 3

def get_noise_factor(desc: str) -> int:
    d = desc.lower()
    if "powershell" in d: return 5
    if "discovery"  in d: return 4
    return 2

def calculate_score(alert: dict) -> float:
    desc     = alert.get("rule", {}).get("description", "")
    severity = alert.get("rule", {}).get("level", 1)
    agent    = alert.get("agent", {}).get("name", "")
    t = get_technique_score(desc)
    a = get_asset_value(agent)
    p = get_privilege_score(desc)
    c = severity
    n = get_noise_factor(desc)
    return round((t * a * p * c) / n, 2)

def get_priority(score: float) -> str:
    if score >= 400: return "Critical"
    if score >= 250: return "High"
    if score >= 100: return "Medium"
    return "Low"

def infer_attack_type(desc: str) -> str:
    d = desc.lower()
    if "credential"   in d:                        return "Credential Access"
    if "mimikatz"     in d:                        return "Credential Dumping"
    if "powershell"   in d:                        return "Execution"
    if "discovery"    in d:                        return "Discovery"
    if "lateral"      in d or "smb"     in d:      return "Lateral Movement"
    if "privilege"    in d:                        return "Privilege Escalation"
    if "persistence"  in d:                        return "Persistence"
    if "defense evasion" in d or "amsi" in d:      return "Defense Evasion"
    if "integrity"    in d or "checksum" in d:     return "File Integrity"
    if "netstat"      in d or "port"     in d:     return "Network Discovery"
    if "apparmor"     in d:                        return "Host Protection"
    if "rootkit"      in d:                        return "Rootkit"
    return "Other"


# ─── Agentic AI — Unique Per Alert ────────────────────────────────────────────
def build_ai_analysis(description: str, severity: int, agent_name: str,
                      attack_type: str, score: float, priority: str) -> dict:
    cache_key = hashlib.sha256(
        f"{description}|{severity}|{agent_name}".encode()
    ).hexdigest()

    if cache_key in _ai_cache:
        return _ai_cache[cache_key]

    fallback_classification = (
        f"{attack_type} detected on {agent_name}. "
        f"Wazuh severity level {severity} with formula risk score {score}. "
        f"Priority: {priority}. Alert: \"{description}\"."
    )
    fallback_steps = _rule_based_steps(description, attack_type, agent_name, severity)

    if not openai_client:
        result = {"ai_classification": fallback_classification, "ai_response": fallback_steps}
        _ai_cache[cache_key] = result
        return result

    try:
        classification = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": (
                    "You are a senior cybersecurity analyst. "
                    "Classify the alert in 2-3 sentences: identify the specific attack technique, "
                    "the likely attacker goal, and why this is dangerous. Be specific to the alert."
                )},
                {"role": "user", "content": (
                    f"Alert: {description}\n"
                    f"Host: {agent_name}\n"
                    f"Wazuh Severity: {severity}\n"
                    f"Attack Category: {attack_type}\n"
                    f"Risk Score: {score} ({priority})"
                )},
            ],
            max_tokens=200,
            temperature=0.3,
        ).choices[0].message.content.strip()
    except Exception:
        classification = fallback_classification

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": (
                    "You are a SOC incident responder. "
                    "Given the alert, provide EXACTLY this structure:\n\n"
                    "IMMEDIATE ACTIONS (do these first):\n"
                    "1. [specific action]\n"
                    "2. [specific action]\n"
                    "3. [specific action]\n\n"
                    "INVESTIGATION STEPS:\n"
                    "1. [specific step]\n"
                    "2. [specific step]\n\n"
                    "PATCH / REMEDIATION:\n"
                    "1. [specific fix]\n"
                    "2. [specific fix]\n\n"
                    "Be specific to this exact alert. Do not give generic advice."
                )},
                {"role": "user", "content": (
                    f"Alert: {description}\n"
                    f"Host: {agent_name}\n"
                    f"Wazuh Severity: {severity}\n"
                    f"Attack Category: {attack_type}\n"
                    f"Risk Score: {score} ({priority})"
                )},
            ],
            max_tokens=400,
            temperature=0.2,
        ).choices[0].message.content.strip()
    except Exception:
        response = fallback_steps

    result = {"ai_classification": classification, "ai_response": response}
    _ai_cache[cache_key] = result
    return result


def _rule_based_steps(desc: str, attack_type: str, agent: str, severity: int) -> str:
    d = desc.lower()

    if "credential" in d or "mimikatz" in d:
        return (
            "IMMEDIATE ACTIONS:\n"
            f"1. Isolate {agent} from the network immediately.\n"
            "2. Force password reset for ALL accounts that logged into this host.\n"
            "3. Revoke and rotate all service account credentials.\n\n"
            "INVESTIGATION STEPS:\n"
            "1. Check LSASS process memory access logs in Sysmon Event ID 10.\n"
            "2. Review all successful authentications from this host in last 24h.\n\n"
            "PATCH / REMEDIATION:\n"
            "1. Enable Credential Guard on Windows (requires UEFI + Secure Boot).\n"
            "2. Restrict LSASS access via Attack Surface Reduction rules in Defender."
        )
    if "lateral" in d or "smb" in d:
        return (
            "IMMEDIATE ACTIONS:\n"
            f"1. Block SMB (port 445) traffic from {agent} at the firewall.\n"
            "2. Identify destination hosts and isolate them too.\n"
            "3. Disable the account used for lateral movement.\n\n"
            "INVESTIGATION STEPS:\n"
            "1. Review Sysmon Event ID 3 (network connections) from this host.\n"
            "2. Check Windows Event 4624 (logon) on destination hosts.\n\n"
            "PATCH / REMEDIATION:\n"
            "1. Enable SMB signing to prevent relay attacks.\n"
            "2. Segment the network — servers should not reach workstations via SMB."
        )
    if "powershell" in d:
        return (
            "IMMEDIATE ACTIONS:\n"
            f"1. Kill the suspicious PowerShell process on {agent}.\n"
            "2. Check for scheduled tasks or startup entries created.\n"
            "3. Capture memory dump before isolating.\n\n"
            "INVESTIGATION STEPS:\n"
            "1. Review PowerShell Script Block Logging (Event ID 4104).\n"
            "2. Check for Base64-encoded commands in process arguments.\n\n"
            "PATCH / REMEDIATION:\n"
            "1. Set PowerShell execution policy to AllSigned.\n"
            "2. Enable Constrained Language Mode via AppLocker or WDAC."
        )
    if "privilege" in d:
        return (
            "IMMEDIATE ACTIONS:\n"
            f"1. Revoke elevated privileges on {agent} immediately.\n"
            "2. Disable the account attempting privilege escalation.\n"
            "3. Check what was done with elevated privileges.\n\n"
            "INVESTIGATION STEPS:\n"
            "1. Review Windows Event 4672 (special privilege assigned).\n"
            "2. Check Event 4688 (process creation) for suspicious children.\n\n"
            "PATCH / REMEDIATION:\n"
            "1. Apply principle of least privilege — remove local admin rights.\n"
            "2. Enable UAC at highest level and require admin approval."
        )
    if "integrity" in d or "checksum" in d:
        return (
            "IMMEDIATE ACTIONS:\n"
            f"1. Identify which file changed on {agent} and by which process.\n"
            "2. Compare file hash against known-good baseline.\n"
            "3. If system file — consider OS reinstall.\n\n"
            "INVESTIGATION STEPS:\n"
            "1. Check Wazuh FIM (File Integrity Monitoring) logs for the exact path.\n"
            "2. Review who/what process modified the file.\n\n"
            "PATCH / REMEDIATION:\n"
            "1. Restore file from verified backup.\n"
            "2. Tighten file permissions — restrict write access to system directories."
        )
    if "apparmor" in d:
        return (
            "IMMEDIATE ACTIONS:\n"
            f"1. Review what process was denied by AppArmor on {agent}.\n"
            "2. Determine if the denial was legitimate or an attack attempt.\n"
            "3. Do not disable AppArmor — it is doing its job.\n\n"
            "INVESTIGATION STEPS:\n"
            "1. Check /var/log/syslog for full AppArmor denial context.\n"
            "2. Identify the parent process that launched the denied operation.\n\n"
            "PATCH / REMEDIATION:\n"
            "1. If legitimate — update AppArmor profile carefully.\n"
            "2. If malicious — isolate host and investigate parent process."
        )
    if "netstat" in d or "port" in d:
        return (
            "IMMEDIATE ACTIONS:\n"
            f"1. Review what new ports opened on {agent}.\n"
            "2. Check if any unauthorized services started.\n"
            "3. Compare against known baseline of expected listeners.\n\n"
            "INVESTIGATION STEPS:\n"
            "1. Run netstat -tulnp to identify processes on new ports.\n"
            "2. Check systemd/init logs for recently started services.\n\n"
            "PATCH / REMEDIATION:\n"
            "1. Close unauthorized ports via firewall rules.\n"
            "2. Remove or disable unexpected services."
        )

    return (
        f"IMMEDIATE ACTIONS:\n"
        f"1. Investigate {agent} — review running processes and network connections.\n"
        f"2. Preserve system logs before any changes.\n"
        f"3. Notify SOC lead — severity level {severity} requires attention.\n\n"
        f"INVESTIGATION STEPS:\n"
        f"1. Correlate this alert with other alerts from same host in last 1 hour.\n"
        f"2. Review Wazuh alert details for full context.\n\n"
        f"PATCH / REMEDIATION:\n"
        f"1. Apply relevant security patches for detected {attack_type} vector.\n"
        f"2. Review and harden security controls on {agent}."
    )


# ─── Alert Loading ────────────────────────────────────────────────────────────
MOCK_ALERTS = [
    {"rule": {"description": "Mimikatz credential dumping detected",          "level": 14}, "agent": {"name": "WIN-DC01"},           "timestamp": "2025-04-20T10:01:00.000Z"},
    {"rule": {"description": "PowerShell Empire C2 execution detected",       "level": 12}, "agent": {"name": "WIN-WORKSTATION-03"}, "timestamp": "2025-04-20T10:05:00.000Z"},
    {"rule": {"description": "Lateral movement via SMB share enumeration",    "level": 13}, "agent": {"name": "WIN-SERVER-02"},      "timestamp": "2025-04-20T10:08:00.000Z"},
    {"rule": {"description": "Privilege escalation via administrator token",  "level": 11}, "agent": {"name": "WIN-WORKSTATION-01"}, "timestamp": "2025-04-20T10:12:00.000Z"},
    {"rule": {"description": "Persistence via Registry Run key modification", "level": 10}, "agent": {"name": "WIN-DC01"},           "timestamp": "2025-04-20T10:15:00.000Z"},
    {"rule": {"description": "Defense evasion via AMSI bypass",               "level": 12}, "agent": {"name": "WIN-SERVER-02"},      "timestamp": "2025-04-20T10:18:00.000Z"},
    {"rule": {"description": "Network discovery scan (nmap-style)",           "level":  6}, "agent": {"name": "WIN-WORKSTATION-02"}, "timestamp": "2025-04-20T10:20:00.000Z"},
    {"rule": {"description": "Integrity checksum changed on system binary",   "level":  9}, "agent": {"name": "WIN-SERVER-02"},      "timestamp": "2025-04-20T10:22:00.000Z"},
]

def load_raw_alerts() -> list[dict]:
    if ingested_alerts:
        return list(ingested_alerts)

    if os.path.exists(ALERTS_FILE):
        results = []
        try:
            with open(ALERTS_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        results.append(json.loads(line))
                    except Exception:
                        continue
        except Exception:
            pass
        if results:
            return results

    return []


def build_alert_object(raw: dict) -> Optional[dict]:
    description = raw.get("rule", {}).get("description", "Unknown alert")
    severity    = raw.get("rule", {}).get("level", 1)
    agent_name  = raw.get("agent", {}).get("name", "unknown")
    timestamp   = raw.get("timestamp", datetime.utcnow().isoformat() + "Z")

    if "cis" in description.lower():
        return None

    score       = calculate_score(raw)
    priority    = get_priority(score)
    attack_type = infer_attack_type(description)
    ai          = build_ai_analysis(description, severity, agent_name, attack_type, score, priority)

    alert_id = hashlib.sha256(
        f"{agent_name}|{description}|{timestamp}".encode()
    ).hexdigest()[:14]

    return {
        "id":                alert_id,
        "description":       description,
        "severity":          severity,
        "agent_name":        agent_name,
        "formula_score":     score,
        "priority":          priority,
        "attack_type":       attack_type,
        "mitre_tactic":      attack_type,
        "ai_classification": ai["ai_classification"],
        "ai_response":       ai["ai_response"],
        "timestamp":         timestamp,
        "status":            alert_actions.get(alert_id, "Open"),
    }


def get_all_alerts() -> list[dict]:
    raw_list  = load_raw_alerts() or MOCK_ALERTS
    processed = []
    for raw in raw_list:
        obj = build_alert_object(raw)
        if obj:
            processed.append(obj)
    processed.sort(key=lambda x: x["formula_score"], reverse=True)
    return processed


# ─── Endpoints ────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "running", "api": "ThreatWatch", "version": "2.0"}


@app.get("/alerts")
def get_alerts(
    severity:    Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    search:      Optional[str] = Query(None),
):
    alerts = get_all_alerts()
    if severity:
        alerts = [a for a in alerts if a["priority"].lower() == severity.lower()]
    if attack_type and attack_type != "All":
        alerts = [a for a in alerts if a["attack_type"].lower() == attack_type.lower()]
    if search:
        q = search.lower()
        alerts = [a for a in alerts if
                  q in a["description"].lower() or
                  q in a["agent_name"].lower()  or
                  q in a["attack_type"].lower()]
    return {"alerts": alerts, "total": len(alerts)}


@app.get("/alerts/summary")
def get_summary():
    alerts = get_all_alerts()
    by_p   = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    atk    = {}
    agt    = {}
    for a in alerts:
        by_p[a["priority"]]   = by_p.get(a["priority"],   0) + 1
        atk[a["attack_type"]] = atk.get(a["attack_type"], 0) + 1
        agt[a["agent_name"]]  = agt.get(a["agent_name"],  0) + 1
    top_atk = sorted(atk.items(), key=lambda x: x[1], reverse=True)[:5]
    top_agt = sorted(agt.items(), key=lambda x: x[1], reverse=True)
    return {
        "total":    len(alerts),
        "critical": by_p["Critical"],
        "high":     by_p["High"],
        "medium":   by_p["Medium"],
        "low":      by_p["Low"],
        "top_attack_categories": [{"name": k, "count": v} for k, v in top_atk],
        "most_affected_agent":   top_agt[0][0] if top_agt else "N/A",
    }


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    for a in get_all_alerts():
        if a["id"] == alert_id:
            return a
    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/refresh")
def refresh():
    _ai_cache.clear()
    return {"status": "refreshed", "alert_count": len(get_all_alerts())}


# ─── Action endpoints ─────────────────────────────────────────────────────────
class ActionRequest(BaseModel):
    action: str

@app.post("/alerts/{alert_id}/action")
def set_action(alert_id: str, body: ActionRequest):
    valid = {"Escalated", "Investigating", "Resolved", "Open"}
    if body.action not in valid:
        raise HTTPException(status_code=400, detail=f"Action must be one of {valid}")
    alert_actions[alert_id] = body.action
    return {"alert_id": alert_id, "status": body.action}

@app.get("/alerts/{alert_id}/action")
def get_action(alert_id: str):
    return {"alert_id": alert_id, "status": alert_actions.get(alert_id, "Open")}


# ─── SSE Live Stream ──────────────────────────────────────────────────────────
@app.get("/alerts/stream/live")
async def live_stream():
    async def generator():
        seen_ids: set[str] = set()
        for a in get_all_alerts():
            seen_ids.add(a["id"])

        while True:
            await asyncio.sleep(5)
            try:
                current = get_all_alerts()
                for alert in current:
                    if alert["id"] not in seen_ids:
                        seen_ids.add(alert["id"])
                        yield f"data: {json.dumps(alert)}\n\n"
                for alert in current:
                    if alert_actions.get(alert["id"]) != alert.get("status"):
                        alert["status"] = alert_actions.get(alert["id"], "Open")
                        yield f"data: {json.dumps({'type':'status_update','id':alert['id'],'status':alert['status']})}\n\n"
            except Exception:
                pass

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── /ingest — receives alerts from Ubuntu forwarder ─────────────────────────
@app.post("/ingest")
async def ingest_alert(alert: dict):
    desc  = alert.get("rule", {}).get("description", "")
    agent = alert.get("agent", {}).get("name", "")
    ts    = alert.get("timestamp", "")
    key   = hashlib.sha256(f"{agent}|{desc}|{ts}".encode()).hexdigest()[:14]

    for existing in ingested_alerts:
        e_desc  = existing.get("rule", {}).get("description", "")
        e_agent = existing.get("agent", {}).get("name", "")
        e_ts    = existing.get("timestamp", "")
        e_key   = hashlib.sha256(f"{e_agent}|{e_desc}|{e_ts}".encode()).hexdigest()[:14]
        if e_key == key:
            return {"status": "duplicate", "id": key}

    ingested_alerts.append(alert)

    if len(ingested_alerts) > 500:
        ingested_alerts.pop(0)

    obj = build_alert_object(alert)
    if obj:
        return {"status": "saved", "id": obj["id"]}
    return {"status": "skipped (CIS or invalid)"}
