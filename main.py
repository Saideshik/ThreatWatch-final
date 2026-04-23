from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def root():
    return {"status": "running"}

@app.get("/alerts")
def alerts():
    return {"alerts": [{"id": "test", "description": "Test alert", "severity": 5, "agent_name": "test-host", "formula_score": 100, "priority": "Medium", "attack_type": "Test", "mitre_tactic": "Test", "ai_classification": "Test classification", "ai_response": "Test response", "timestamp": "2025-01-01T00:00:00Z", "status": "Open"}], "total": 1}

@app.get("/alerts/summary")
def summary():
    return {"total": 1, "critical": 0, "high": 0, "medium": 1, "low": 0, "top_attack_categories": [{"name": "Test", "count": 1}], "most_affected_agent": "test-host"}
