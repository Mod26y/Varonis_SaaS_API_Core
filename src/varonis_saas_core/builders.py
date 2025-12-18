from .constants import MAX_DAYS_BACK
from .errors import InvalidQueryError

def _validate_time_mode(start, end, last_days):
    modes = [bool(start or end), bool(last_days)]
    if sum(modes) > 1:
        raise InvalidQueryError("Multiple time modes specified")

def build_alert_search(*, last_days=None, **kwargs) -> dict:
    _validate_time_mode(None, None, last_days)
    return {
        "entity": "Alert",
        "filters": {"last_days": last_days or MAX_DAYS_BACK},
        "order": "asc",
    }

def build_event_search(*, last_days=None, **kwargs) -> dict:
    _validate_time_mode(None, None, last_days)
    return {
        "entity": "Event",
        "filters": {"last_days": last_days or MAX_DAYS_BACK},
        "order": "desc",
    }
