from varonis_saas_core.client import _to_search_v2_payload
from varonis_saas_core.builders import build_event_search

def test_translation_produces_search_v2_schema():
    req = build_event_search(last_days=1)
    payload = _to_search_v2_payload(req)
    assert "query" in payload and "rows" in payload and "requestParams" in payload
    assert payload["query"]["entityName"] == "Event"
    assert isinstance(payload["rows"]["columns"], list)
    assert isinstance(payload["query"]["filter"]["filters"], list)
