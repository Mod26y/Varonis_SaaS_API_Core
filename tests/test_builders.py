from datetime import datetime, timezone
import pytest
from varonis_saas_core.builders import build_alert_search, build_event_search
from varonis_saas_core.errors import InvalidQueryError

def test_time_mode_conflict():
    with pytest.raises(InvalidQueryError):
        build_alert_search(start_time=datetime.now(timezone.utc), last_days=1)

def test_event_builder_iso():
    start = datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc)
    q = build_event_search(start_time=start, end_time=start)
    assert q["filters"]["start_time"].endswith("+00:00")
