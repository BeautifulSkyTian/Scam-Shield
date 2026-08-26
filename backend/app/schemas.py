from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime

class AnalyzeRequest(BaseModel):
    message: str = Field(min_length=1)
    sender: str | None = None
    url: str | None = None

class RiskReason(BaseModel):
    type: str
    explanation: str

class AnalyzeResponse(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    category: str
    summary: str
    reasons: list[RiskReason]
    recommended_action: str

class AnalysisHistoryItem(BaseModel):
    id: int
    message: str
    sender: str | None
    url: str | None

    risk_score: int
    risk_level: str
    category: str
    summary: str
    reasons: list[RiskReason]
    recommended_action: str

    created_at: datetime

    model_config = {
        "from_attributes": True
    }