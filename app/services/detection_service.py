import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Incident, SecurityEvent


AUTH_EVENT = "authentication"

NETWORK_EVENT_TYPES = {
    "network",
    "network_connection",
    "network_flow",
    "firewall_connection",
}

PRIVILEGED_EVENT_TYPES = {
    "privilege_escalation",
    "privilege_change",
    "privilege",
}

PRIVILEGED_ACTIONS = {
    "sudo",
    "su",
    "usermod",
    "user_modification",
    "group_add",
    "add_to_group",
    "add_admin",
    "grant_admin",
    "role_assignment",
    "assume_role",
    "iam_policy_change",
    "setuid",
}

SUSPICIOUS_AUTH_FLAGS = {
    "new_device",
    "impossible_travel",
    "mfa_bypass",
    "suspicious_location",
    "outside_business_hours",
}


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def calculate_risk_score(
    base_score: int,
    event_count: int = 1,
    baseline_count: int = 1,
) -> int:
    base = max(0, min(100, int(base_score)))
    excess = max(0, int(event_count) - int(baseline_count))
    return min(100, base + min(10, excess * 2))


def severity_for_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def recent_auth_failures(
    db: Session,
    event: SecurityEvent,
    minutes: int,
) -> list[SecurityEvent]:
    if not event.source_ip:
        return []

    end = as_utc(event.occurred_at)
    start = end - timedelta(minutes=minutes)

    query = (
        select(SecurityEvent)
        .where(
            SecurityEvent.event_type == AUTH_EVENT,
            SecurityEvent.outcome == "failure",
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.occurred_at >= start,
            SecurityEvent.occurred_at <= end,
        )
        .order_by(SecurityEvent.occurred_at.asc())
    )

    results = list(db.scalars(query).all())

    if event.username:
        results = [
            item for item in results
            if item.username == event.username
        ]

    return results


def save_incident(
    db: Session,
    event: SecurityEvent,
    rule_id: str,
    title: str,
    description: str,
    base_score: int,
    baseline_count: int,
    evidence: list[SecurityEvent],
) -> Incident:
    evidence = [item for item in evidence if item.id]

    event_ids = list(dict.fromkeys(
        item.id for item in evidence
    ))

    if event.id not in event_ids:
        event_ids.append(event.id)

    event_time = as_utc(event.occurred_at)
    hour = event_time.strftime("%Y-%m-%dT%H")

    fingerprint_data = "|".join([
        rule_id,
        event.source_ip or "unknown-ip",
        event.username or "unknown-user",
        hour,
    ])

    fingerprint = hashlib.sha256(
        fingerprint_data.encode()
    ).hexdigest()

    score = calculate_risk_score(
        base_score,
        len(event_ids),
        baseline_count,
    )

    first_seen = min(as_utc(x.occurred_at) for x in evidence)
    last_seen = max(as_utc(x.occurred_at) for x in evidence)

    incident = db.scalar(
        select(Incident).where(
            Incident.fingerprint == fingerprint
        )
    )

    if incident is None:
        incident = Incident(
            fingerprint=fingerprint,
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity_for_score(score),
            risk_score=score,
            status="open",
            source_ip=event.source_ip,
            username=event.username,
            first_seen=first_seen,
            last_seen=last_seen,
            event_count=len(event_ids),
            evidence_event_ids=event_ids[-100:],
        )
        db.add(incident)
    else:
        combined = list(dict.fromkeys(
            (incident.evidence_event_ids or []) + event_ids
        ))

        incident.description = description
        incident.evidence_event_ids = combined[-100:]
        incident.event_count = len(combined)
        incident.risk_score = max(incident.risk_score, score)
        incident.severity = severity_for_score(
            incident.risk_score
        )
        incident.first_seen = min(
            as_utc(incident.first_seen), first_seen
        )
        incident.last_seen = max(
            as_utc(incident.last_seen), last_seen
        )

    db.commit()
    db.refresh(incident)
    return incident


def detect_brute_force(
    db: Session,
    event: SecurityEvent,
) -> dict | None:
    if (
        event.event_type != AUTH_EVENT
        or event.outcome != "failure"
        or not event.source_ip
    ):
        return None

    failures = recent_auth_failures(db, event, 10)

    if len(failures) < 5:
        return None

    return {
        "rule_id": "BRUTE_FORCE_AUTH",
        "title": "Brute-force authentication activity",
        "description": (
            f"{len(failures)} failed logins from "
            f"{event.source_ip} within 10 minutes."
        ),
        "score": 80,
        "baseline": 5,
        "evidence": failures,
    }


def detect_suspicious_authentication(
    db: Session,
    event: SecurityEvent,
) -> dict | None:
    if (
        event.event_type != AUTH_EVENT
        or event.outcome != "success"
    ):
        return None

    details = event.details or {}

    indicators = [
        key for key in SUSPICIOUS_AUTH_FLAGS
        if details.get(key) is True
    ]

    failures = recent_auth_failures(db, event, 15)

    if len(failures) >= 3:
        indicators.append("success_after_repeated_failures")
        reason = (
            f"Successful login after {len(failures)} "
            "failed attempts from the same IP and username."
        )
    elif indicators:
        reason = (
            "Suspicious authentication indicators: "
            + ", ".join(indicators)
        )
    else:
        return None

    return {
        "rule_id": "SUSPICIOUS_AUTH",
        "title": "Suspicious authentication pattern",
        "description": reason,
        "score": 75,
        "baseline": 4 if failures else 1,
        "evidence": failures + [event],
    }


def destination_port(event: SecurityEvent) -> int | None:
    details = event.details or {}
    value = details.get(
        "destination_port",
        details.get("dst_port"),
    )

    try:
        port = int(value)
    except (TypeError, ValueError):
        return None

    return port if 1 <= port <= 65535 else None


def detect_port_scan(
    db: Session,
    event: SecurityEvent,
) -> dict | None:
    if (
        event.event_type not in NETWORK_EVENT_TYPES
        or not event.source_ip
        or destination_port(event) is None
    ):
        return None

    end = as_utc(event.occurred_at)
    start = end - timedelta(minutes=5)

    query = (
        select(SecurityEvent)
        .where(
            SecurityEvent.event_type.in_(NETWORK_EVENT_TYPES),
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.occurred_at >= start,
            SecurityEvent.occurred_at <= end,
        )
        .order_by(SecurityEvent.occurred_at.asc())
    )

    events = list(db.scalars(query).all())

    ports = {
        port
        for item in events
        if (port := destination_port(item)) is not None
    }

    if len(ports) < 10:
        return None

    return {
        "rule_id": "PORT_SCAN",
        "title": "Possible network port scan",
        "description": (
            f"{event.source_ip} contacted {len(ports)} "
            "unique destination ports within 5 minutes."
        ),
        "score": 85,
        "baseline": 10,
        "evidence": events,
    }


def detect_privilege_escalation(
    event: SecurityEvent,
) -> dict | None:
    event_type = event.event_type.lower()
    details = event.details or {}

    action = str(
        details.get("action")
        or details.get("operation")
        or details.get("event_action")
        or ""
    ).lower().strip()

    explicit = (
        details.get("privilege_escalation") is True
        or details.get("privilege_change") is True
    )

    if not (
        event_type in PRIVILEGED_EVENT_TYPES
        or explicit
        or action in PRIVILEGED_ACTIONS
    ):
        return None

    return {
        "rule_id": "PRIVILEGE_ESCALATION",
        "title": "Privilege escalation activity",
        "description": (
            f"Potential privilege escalation. "
            f"Event type: {event_type}; action: "
            f"{action or 'not specified'}."
        ),
        "score": 95,
        "baseline": 1,
        "evidence": [event],
    }


def evaluate_event(
    db: Session,
    event: SecurityEvent,
) -> list[Incident]:
    findings = [
        detect_brute_force(db, event),
        detect_suspicious_authentication(db, event),
        detect_port_scan(db, event),
        detect_privilege_escalation(event),
    ]

    incidents = []

    for finding in findings:
        if finding is None:
            continue

        incidents.append(
            save_incident(
                db=db,
                event=event,
                rule_id=finding["rule_id"],
                title=finding["title"],
                description=finding["description"],
                base_score=finding["score"],
                baseline_count=finding["baseline"],
                evidence=finding["evidence"],
            )
        )

    return incidents
