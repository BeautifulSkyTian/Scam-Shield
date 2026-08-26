from fastapi import FastAPI

from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.services.ai_service import analyze_scam

app = FastAPI(
    title="Scam Guard API",
    version="0.1.0"
)

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_message(request: AnalyzeRequest):
    return analyze_scam(request)