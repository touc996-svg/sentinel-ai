from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import SecurityEventCreate, SecurityEventRead
from app.services import event_service

router = APIRouter(
    prefix="/api/v1/events",
    tags=["Security Events"],
)


@router.post(
    "",
    response_model=SecurityEventRead,
    status_code=status.HTTP_201_CREATED,
)
def ingest_event(
    payload: SecurityEventCreate,
    db: Session = Depends(get_db),
):
    return event_service.create_event(db, payload)


@router.get("", response_model=list[SecurityEventRead])
def get_events(
    event_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    return event_service.list_events(
        db=db,
        event_type=event_type,
        limit=limit,
        offset=offset,
    )


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
):
    event = event_service.get_event(db, event_id)

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security event not found.",
        )

    return event
