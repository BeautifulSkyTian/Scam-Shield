from datetime import datetime

from sqlalchemy import Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.database import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True)

    message: Mapped[str] = mapped_column(Text)
    sender: Mapped[str | None] = mapped_column(String, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    platform: Mapped[str | None] = mapped_column(String, nullable=True)
    page_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    message_id: Mapped[str | None] = mapped_column(String, nullable=True)

    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)

    summary: Mapped[str] = mapped_column(Text)

    reasons: Mapped[list] = mapped_column(JSON)

    recommended_action: Mapped[str] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)