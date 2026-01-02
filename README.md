# Varonis SaaS Core API

Platform-agnostic Python core for interacting with the Varonis SaaS Security API.

## Install

From source:
```bash
python -m pip install .
```

## Quick auth check

```python
from varonis_saas_core import VaronisConfig, VaronisClient

cfg = VaronisConfig("https://YOUR_TENANT.varonis.com", "YOUR_API_KEY", integration_name="My Integration")
client = VaronisClient(cfg)
client.authenticate()
print("ok")
```

## First query: today's events (UTC)

```python
from datetime import datetime, timezone
from varonis_saas_core import VaronisConfig, VaronisClient, build_event_search, EventMapper

cfg = VaronisConfig("https://YOUR_TENANT.varonis.com", "YOUR_API_KEY", integration_name="My Integration")
client = VaronisClient(cfg)

start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
end = datetime.now(timezone.utc)

req = build_event_search(start_time=start, end_time=end)
raw = client.search(req, max_rows=500)
events = EventMapper().map(raw)

print(f"events: {len(events)}")
```

## Usage examples

### Retrieve Enumeration Values (Threat Models)

```python
from varonis_saas_core import VaronisConfig, VaronisClient, THREAT_MODEL_ENUM_ID

cfg = VaronisConfig(
    "https://YOUR_TENANT.varonis.com",
    "YOUR_API_KEY",
    "Enum Example",
)
client = VaronisClient(cfg)

enum_values = client.get_enum(THREAT_MODEL_ENUM_ID)

print(f"Threat models returned: {len(enum_values)}")
print(enum_values[:3])
```

### Search Alerts (Last 7 Days)

```python
from varonis_saas_core import (
    VaronisConfig,
    VaronisClient,
    build_alert_search,
    AlertMapper,
)

cfg = VaronisConfig(
    "https://YOUR_TENANT.varonis.com",
    "YOUR_API_KEY",
    "Alert Search Example",
)
client = VaronisClient(cfg)

request = build_alert_search(last_days=7)
raw = client.search(request, max_rows=10)
alerts = AlertMapper().map(raw)

print(f"Alerts returned: {len(alerts)}")
print(alerts[:1])
```

### Search Events (Last 1 Day)

```python
from varonis_saas_core import (
    VaronisConfig,
    VaronisClient,
    build_event_search,
    EventMapper,
)

cfg = VaronisConfig(
    "https://YOUR_TENANT.varonis.com",
    "YOUR_API_KEY",
    "Event Search Example",
)
client = VaronisClient(cfg)

request = build_event_search(last_days=1)
raw = client.search(request, max_rows=10)
events = EventMapper().map(raw)

print(f"Events returned: {len(events)}")
print(events[:1])
```

### Search Events for a Specific Alert ID

```python
from varonis_saas_core import (
    VaronisConfig,
    VaronisClient,
    build_event_search,
    EventMapper,
)

ALERT_ID = "PUT_ALERT_GUID_HERE"

cfg = VaronisConfig(
    "https://YOUR_TENANT.varonis.com",
    "YOUR_API_KEY",
    "Events by Alert Example",
)
client = VaronisClient(cfg)

request = build_event_search(
    alert_ids=[ALERT_ID],
    last_days=30,
)
raw = client.search(request, max_rows=50)
events = EventMapper().map(raw)

print(f"Events for alert {ALERT_ID}: {len(events)}")
print(events[:1])
```

### Update Alert Status
```python
from varonis_saas_core import VaronisConfig, VaronisClient
from varonis_saas_core.constants import ALERT_STATUSES, CLOSE_REASONS

ALERT_ID = "PUT_ALERT_GUID_HERE"

cfg = VaronisConfig(
    "https://YOUR_TENANT.varonis.com",
    "YOUR_API_KEY",
    "Update Status Example",
)
client = VaronisClient(cfg)

client.update_alert_status(
    alert_ids=[ALERT_ID],
    status_id=ALERT_STATUSES["closed"],
    close_reason_id=CLOSE_REASONS["true positive"],
)

print("ALERT STATUS UPDATED")
```

### Add a Note to an Alert
```python
from varonis_saas_core import VaronisConfig, VaronisClient

ALERT_ID = "PUT_ALERT_GUID_HERE"

cfg = VaronisConfig(
    "https://YOUR_TENANT.varonis.com",
    "YOUR_API_KEY",
    "Add Note Example",
)
client = VaronisClient(cfg)

client.add_alert_note(
    alert_ids=[ALERT_ID],
    note="Reviewed via API example script.",
)

print("ALERT NOTE ADDED")
```

## Run tests

```bash
python -m pip install -r requirements-dev.txt  # optional if you maintain it
python -m pytest
```

## Errors

- `AuthenticationError`: auth failure (bad key, wrong tenant, etc.)
- `ApiRequestError`: API non-200 responses or parsing failures
- `InvalidQueryError`: invalid builder inputs


## Disclaimer and Risk Assumption

This example code is not affiliated with, endorsed by, guaranteed by, or supported by Varonis. It is provided on an “as is” basis, without warranties of any kind. You assume all risk associated with downloading, using, modifying, or redistributing this code, in whole or in part.