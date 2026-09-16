from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import SessionLocal
from models.security_log import SecurityLog
from models.security_alert import SecurityAlert

from app.schemas.security_log import (
    SecurityLogCreate,
    SecurityLogResponse
)

from app.services.detection_engine import detect_threats


router = APIRouter(
    prefix="/api/logs",
    tags=["Security Logs"]
)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@router.post(
    "",
    response_model=SecurityLogResponse
)
def create_security_log(
    log: SecurityLogCreate,
    db: Session = Depends(get_db)
):

    # ---------------------------------------------------------
    # 1. Security log létrehozása
    # ---------------------------------------------------------

    db_log = SecurityLog(
        source=log.source,
        source_ip=log.source_ip,
        event_type=log.event_type,
        username=log.username,
        message=log.message,
        severity=log.severity
    )

    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    # ---------------------------------------------------------
    # 2. Detection Engine futtatása
    # ---------------------------------------------------------

    detections = detect_threats(
        source=log.source,
        source_ip=log.source_ip,
        event_type=log.event_type,
        username=log.username,
        message=log.message
    )

    # ---------------------------------------------------------
    # 3. Security Alert-ek létrehozása
    # ---------------------------------------------------------

    for detection in detections:

        alert = SecurityAlert(
            security_log_id=db_log.id,
            rule_name=detection.rule_name,
            severity=detection.severity,
            title=detection.title,
            description=detection.description,
            confidence=detection.confidence,
            status="OPEN"
        )

        db.add(alert)

    db.commit()

    return db_log