from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Multi-Agent SOAR API",
    version="0.1.0",
    description="API skeleton for a SOAR playbook and incident ticketing workflow."
)

class HealthResponse(BaseModel):
    status: str
    service: str

@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(status="ok", service="multi-agent-soar")

@app.get("/api/v1/summary")
def summary():
    return {
        "project": "Multi-Agent SOAR",
        "mode": "skeleton",
        "message": "Replace mocked handlers with real playbook, correlation, and ticketing logic."
    }
