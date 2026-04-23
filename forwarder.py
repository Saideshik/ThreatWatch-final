"""
Reads new Wazuh alerts and sends them to Railway backend every 5 seconds.
Run this on Ubuntu alongside Wazuh:  python3 forwarder.py &
"""
import json, time, requests, os, hashlib

RAILWAY_URL  = "https://threatwatch-production.up.railway.app"  # ← your Railway URL
ALERTS_FILE  = "/var/ossec/logs/alerts/alerts.json"
POLL_SECONDS = 5

seen = set()

def alert_id(raw):
    desc  = raw.get("rule", {}).get("description", "")
    agent = raw.get("agent", {}).get("name", "")
    ts    = raw.get("timestamp", "")
    return hashlib.sha256(f"{agent}|{desc}|{ts}".encode()).hexdigest()[:14]

print("Forwarder started — watching", ALERTS_FILE)

while True:
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                        aid   = alert_id(alert)
                        if aid not in seen:
                            seen.add(aid)
                            requests.post(
                                f"{RAILWAY_URL}/ingest",
                                json=alert,
                                timeout=5
                            )
                            print(f"Forwarded: {alert.get('rule',{}).get('description','?')[:60]}")
                    except Exception as e:
                        print(f"Error: {e}")
    except Exception as e:
        print(f"File error: {e}")
    time.sleep(POLL_SECONDS)
