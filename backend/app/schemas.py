from pydantic import BaseModel, Field, HttpUrl

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