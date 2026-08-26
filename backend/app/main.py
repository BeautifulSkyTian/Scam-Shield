from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AnalysisHistoryItem,
)
from app.services.ai_service import AIServiceError, analyze_scam
from app.database.database import Base, engine, get_db
from app.database.models import Analysis


app = FastAPI(
    title="Scam Guard API",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173", #"chrome-extension://YOUR_EXTENSION_ID",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
        result = analyze_scam(request)

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

        db.add(analysis)
        db.commit()

        return result

    except AIServiceError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error)
        )

    except SQLAlchemyError as error:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Failed to save analysis"
        ) from error


@app.get(
    "/api/history",
    response_model=list[AnalysisHistoryItem]
)
def get_analysis_history(
    db: Session = Depends(get_db)
):
    statement = (
        select(Analysis)
        .order_by(Analysis.created_at.desc())
        .limit(50)
    )

    analyses = db.scalars(statement).all()

    return analyses