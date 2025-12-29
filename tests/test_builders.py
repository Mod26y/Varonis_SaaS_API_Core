from datetime import datetime, timezone
import pytest

from varonis_saas_core.builders import build_alert_search, build_event_search
from varonis_saas_core.errors import InvalidQueryError

def test_alert_builder_last_days():
    q = build_alert_search(last_days=7)
    assert q["entity"] == "Alert"
    assert q["filters"]["last_days"] == 7
    assert q["order"] == "asc"

def test_event_builder_defaults():
    q = build_event_search()
    assert q["entity"] == "Event"
    assert q["order"] == "desc"

def test_conflicting_time_modes_raise():
    with pytest.raises(InvalidQueryError):
        build_alert_search(start_time=datetime.now(timezone.utc), last_days=5)

def test_datetime_serialization_to_iso():
    start = datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc)
    q = build_event_search(start_time=start, end_time=start)
    assert q["filters"]["start_time"].endswith("+00:00")
