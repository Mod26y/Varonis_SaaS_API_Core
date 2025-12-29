from __future__ import annotations
from datetime import datetime, timezone
from .constants import MAX_DAYS_BACK
from .errors import InvalidQueryError

def _ensure_utc_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        raise InvalidQueryError("Datetime must be timezone-aware (UTC recommended).")
    # Normalize to UTC and emit RFC3339-ish ISO string
    return dt.astimezone(timezone.utc).isoformat()

def _validate_time_mode(start: datetime | None, end: datetime | None, last_days: int | None,
                        ingest_from: datetime | None, ingest_to: datetime | None) -> None:
    modes = [
        bool(start or end),
        bool(last_days),
        bool(ingest_from or ingest_to),
    ]
    if sum(modes) > 1:
        raise InvalidQueryError("Multiple time modes specified.")
    if (start and end) and (end < start):
        raise InvalidQueryError("end_time must be >= start_time.")
    if last_days is not None and last_days < 1:
        raise InvalidQueryError("last_days must be >= 1.")

def build_alert_search(
    *,
    alert_ids: list[str] | None = None,
    threat_model_ids: list[str] | None = None,
    alert_statuses: list[str] | None = None,
    alert_severities: list[str] | None = None,
    alert_category_ids: list[str] | None = None,
    device_names: list[str] | None = None,
    user_names: list[str] | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    ingest_time_from: datetime | None = None,
    ingest_time_to: datetime | None = None,
    last_days: int | None = None,
    extra_fields: list[str] | None = None,
    descending: bool = False,
) -> dict:
    _validate_time_mode(start_time, end_time, last_days, ingest_time_from, ingest_time_to)
    return {
        "entity": "Alert",
        "filters": {
            "alert_ids": alert_ids,
            "threat_model_ids": threat_model_ids,
            "alert_statuses": alert_statuses,
            "alert_severities": alert_severities,
            "alert_category_ids": alert_category_ids,
            "device_names": device_names,
            "user_names": user_names,
            "start_time": _ensure_utc_iso(start_time),
            "end_time": _ensure_utc_iso(end_time),
            "ingest_time_from": _ensure_utc_iso(ingest_time_from),
            "ingest_time_to": _ensure_utc_iso(ingest_time_to),
            "last_days": last_days if last_days is not None else MAX_DAYS_BACK,
        },
        "extra_fields": extra_fields or [],
        "order": "desc" if descending else "asc",
    }

def build_event_search(
    *,
    alert_ids: list[str] | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    last_days: int | None = None,
    extra_fields: list[str] | None = None,
    descending: bool = True,
) -> dict:
    _validate_time_mode(start_time, end_time, last_days, None, None)
    return {
        "entity": "Event",
        "filters": {
            "alert_ids": alert_ids,
            "start_time": _ensure_utc_iso(start_time),
            "end_time": _ensure_utc_iso(end_time),
            "last_days": last_days if last_days is not None else MAX_DAYS_BACK,
        },
        "extra_fields": extra_fields or [],
        "order": "desc" if descending else "asc",
    }
