from varonis_saas_core.builders import build_alert_search
from varonis_saas_core.config import VaronisConfig
from varonis_saas_core.client import VaronisClient

def test_builder_returns_plain_dict():
    q = build_alert_search(last_days=1)
    assert isinstance(q, dict)
    assert "entity" in q
    assert "filters" in q

def test_client_has_authenticate():
    c = VaronisClient(VaronisConfig("https://x", "y"))
    assert hasattr(c, "authenticate")
