from fastapi import FastAPI, HTTPException

from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.services.ai_service import analyze_scam, AIServiceError

app = FastAPI(
    title="Scam Guard API",
    version="0.1.0"
)

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_message(request: AnalyzeRequest):
    try:
        return analyze_scam(request)

    except AIServiceError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error)
        )