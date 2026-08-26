from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.services.ai_service import AIServiceError, analyze_scam
from app.database.database import Base, engine, get_db
from app.database.models import Analysis


app = FastAPI(
    title="Scam Guard API",
    version="0.1.0"
)


# Create database tables if they do not already exist
Base.metadata.create_all(bind=engine)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_message(
    request: AnalyzeRequest,
    db: Session = Depends(get_db)
):
    try:
        # Send the message to the AI analyzer
        result = analyze_scam(request)

        # Create a database record from the request + AI result
        analysis = Analysis(
            message=request.message,
            sender=request.sender,
            url=request.url,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            category=result.category,
            summary=result.summary,
            reasons=[
                reason.model_dump()
                for reason in result.reasons
            ],
            recommended_action=result.recommended_action
        )

        # Save analysis to database
        db.add(analysis)
        db.commit()

        # Return the structured AI result to the extension/client
        return result

    except AIServiceError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error)
        )