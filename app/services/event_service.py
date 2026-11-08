from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models import SecurityEvent
from app.schemas import SecurityEventCreate


def create_event(
    db: Session,
    payload: SecurityEventCreate,
) -> SecurityEvent:
    event = SecurityEvent(**payload.model_dump())

    db.add(event)
    db.commit()
    db.refresh(event)

    from app.services.detection_service import evaluate_event

    evaluate_event(db, event)
    db.refresh(event)

    return event


def get_event(
    db: Session,
    event_id: str,
) -> SecurityEvent | None:
    return db.get(SecurityEvent, event_id)


def list_events(
    db: Session,
    event_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[SecurityEvent]:
    statement = select(SecurityEvent)

    if event_type:
        statement = statement.where(
            SecurityEvent.event_type == event_type
        )

    statement = (
        statement
        .order_by(desc(SecurityEvent.ingested_at))
        .limit(limit)
        .offset(offset)
    )

    return list(db.scalars(statement).all())
