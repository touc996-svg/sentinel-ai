from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Incident
from app.schemas import IncidentRead


router = APIRouter(
    prefix="/api/v1/incidents",
    tags=["Security Incidents"],
)


@router.get("", response_model=list[IncidentRead])
def list_incidents(
    severity: str | None = None,
    incident_status: str | None = Query(
        default=None,
        alias="status",
    ),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    statement = select(Incident)

    if severity:
        statement = statement.where(
            Incident.severity == severity.lower()
        )

    if incident_status:
        statement = statement.where(
            Incident.status == incident_status.lower()
        )

    statement = (
        statement
        .order_by(
            desc(Incident.risk_score),
            desc(Incident.last_seen),
        )
        .limit(limit)
        .offset(offset)
    )

    return list(db.scalars(statement).all())


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security incident not found.",
        )

    return incident
