from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AnalysisHistoryItem,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
)
from app.services.ai_service import AIServiceError, analyze_scam, rate_limit_status
from app.database.database import Base, engine, get_db
from app.database.models import Analysis
from app.core.config import ALLOWED_ORIGINS


app = FastAPI(
    title="Scam Guard API",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


Base.metadata.create_all(bind=engine)


@app.get("/health")
def health_check():
    # Includes remaining free-tier quota for this minute. Worth showing during
    # a demo so a rate-limit stall reads as a quota issue, not a crash.
    return {
        "status": "ok",
        "rate_limit": rate_limit_status(),
    }


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
            platform=request.platform,
            page_url=request.page_url,
            message_id=request.message_id,

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


@app.post(
    "/api/analyze/batch",
    response_model=BatchAnalyzeResponse
)
def analyze_messages_batch(
    request: BatchAnalyzeRequest,
    db: Session = Depends(get_db)
):
    results: list[AnalyzeResponse] = []

    try:
        for message_request in request.messages:
            result = analyze_scam(message_request)

            result.message_id = message_request.message_id

            analysis = Analysis(
                message=message_request.message,
                sender=message_request.sender,
                url=message_request.url,
                platform=message_request.platform,
                page_url=message_request.page_url,
                message_id=message_request.message_id,

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
            results.append(result)

        db.commit()

        return BatchAnalyzeResponse(
            results=results
        )

    except AIServiceError as error:
        db.rollback()

        raise HTTPException(
            status_code=503,
            detail=str(error)
        )

    except SQLAlchemyError as error:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Failed to save batch analysis"
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