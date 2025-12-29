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