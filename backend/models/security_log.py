from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import Base


class SecurityLog(Base):
    __tablename__ = "security_logs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    source_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    username: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        default="INFO",
        nullable=False
    )

    alerts: Mapped[list["SecurityAlert"]] = relationship(
        "SecurityAlert",
        back_populates="security_log",
        cascade="all, delete-orphan"
    )