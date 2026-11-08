import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SecurityEventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=100)
    source_ip: str | None = Field(default=None, max_length=45)
    username: str | None = Field(default=None, max_length=255)
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    occurred_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type", "source")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field cannot be blank.")
        return value

    @field_validator("source_ip")
    @classmethod
    def validate_ip_address(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None

        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("Invalid IP address.") from exc

    @field_validator("username")
    @classmethod
    def clean_username(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("details")
    @classmethod
    def validate_details_size(
        cls,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            serialized = json.dumps(value).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Details must contain JSON-compatible values."
            ) from exc

        if len(serialized) > 16_384:
            raise ValueError("Details cannot exceed 16 KB.")

        return value


class SecurityEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_type: str
    source: str
    source_ip: str | None
    username: str | None
    outcome: str
    occurred_at: datetime
    ingested_at: datetime
    details: dict[str, Any]
