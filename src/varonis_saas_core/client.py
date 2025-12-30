from __future__ import annotations
import json
import ssl
import urllib3
from typing import Any
from .errors import AuthenticationError, ApiRequestError
from .constants import ALERT_STATUSES, ALERT_SEVERITIES
from .attributes import AlertAttributes, EventAttributes

def _ssl_context() -> ssl.SSLContext:
    # Matches the provided Splunk integration behavior.
    ctx = ssl._create_unverified_context()
    ctx.load_default_certs()
    # Legacy connect (mirrors Splunk integration). Harmless if unsupported.
    try:
        ctx.options |= 0x4
    except Exception:
        pass
    return ctx

def _to_search_v2_payload(req: dict) -> dict:
    # Pass-through if caller already provided a Search v2 schema payload.
    if "query" in req and "rows" in req and "requestParams" in req:
        return req

    entity = req.get("entity")
    filters = req.get("filters") or {}
    extra_fields = req.get("extra_fields") or []
    order = (req.get("order") or "desc").lower()
    descending = order == "desc"

    if entity not in ("Alert", "Event"):
        raise ApiRequestError(f"Unsupported entity: {entity}")

    base = {
        "query": {"entityName": entity, "filter": {"filterOperator": 0, "filters": []}},
        "rows": {"columns": [], "filter": [], "grouping": "", "ordering": []},
        "requestParams": {"searchSource": 1, "searchSourceName": "MainTab"},
    }

    def add_condition(path: str, operator: str, values: list[dict]) -> None:
        base["query"]["filter"]["filters"].append({"path": path, "operator": operator, "values": values})

    if entity == "Alert":
        a = AlertAttributes()
        base["rows"]["columns"] = a.get_fields(extra_fields)

        # Required aggregation filter (mirrors Splunk integration)
        add_condition("Alert.AggregationFilter", "Equals", [{"Alert.AggregationFilter": 1}])

        ingest_from = filters.get("ingest_time_from")
        ingest_to = filters.get("ingest_time_to")
        if ingest_from and ingest_to:
            add_condition(a.Alert_IngestTime, "Between", [{a.Alert_IngestTime: ingest_from, f"{a.Alert_IngestTime}0": ingest_to}])
        else:
            start = filters.get("start_time")
            end = filters.get("end_time")
            last_days = filters.get("last_days")
            if start and end:
                add_condition(a.Alert_TimeUTC, "Between", [{a.Alert_TimeUTC: start, f"{a.Alert_TimeUTC}0": end}])
            else:
                add_condition(a.Alert_TimeUTC, "LastDays", [{a.Alert_TimeUTC: last_days, "displayValue": last_days}])

        # IDs
        if filters.get("alert_ids"):
            vals = [{a.Alert_ID: x, "displayValue": x} for x in filters["alert_ids"]]
            add_condition(a.Alert_ID, "In", vals)

        # Threat model ids
        if filters.get("threat_model_ids"):
            vals = [{a.Alert_Rule_ID: x, "displayValue": x} for x in filters["threat_model_ids"]]
            add_condition(a.Alert_Rule_ID, "In", vals)

        # Categories
        if filters.get("alert_category_ids"):
            vals = [{a.Alert_Rule_Category_ID: x} for x in filters["alert_category_ids"]]
            add_condition(a.Alert_Rule_Category_ID, "In", vals)

        # Devices
        if filters.get("device_names"):
            vals = [{a.Alert_Device_HostName: x, "displayValue": x} for x in filters["device_names"]]
            add_condition(a.Alert_Device_HostName, "In", vals)

        # Users
        if filters.get("user_names"):
            vals = [{a.Alert_User_Identity_Name: x, "displayValue": x} for x in filters["user_names"]]
            add_condition(a.Alert_User_Identity_Name, "In", vals)

        # Statuses and severities default like Splunk integration
        statuses = filters.get("alert_statuses") or list(ALERT_STATUSES.keys())
        if statuses:
            vals = [{a.Alert_Status_ID: ALERT_STATUSES[s.lower()], "displayValue": s} for s in statuses]
            add_condition(a.Alert_Status_ID, "In", vals)

        severities = filters.get("alert_severities") or list(ALERT_SEVERITIES.keys())
        if severities:
            vals = [{a.Alert_Rule_Severity_ID: ALERT_SEVERITIES[s.lower()], "displayValue": s} for s in severities]
            add_condition(a.Alert_Rule_Severity_ID, "In", vals)

        base["rows"]["ordering"].append({"path": a.Alert_TimeUTC, "sortOrder": "Desc" if descending else "Asc"})

    else:
        e = EventAttributes()
        base["rows"]["columns"] = e.get_fields(extra_fields)

        if filters.get("alert_ids"):
            vals = [{e.Event_Alert_ID: x, "displayValue": x} for x in filters["alert_ids"]]
            add_condition(e.Event_Alert_ID, "In", vals)

        start = filters.get("start_time")
        end = filters.get("end_time")
        last_days = filters.get("last_days")
        if start and end:
            add_condition(e.Event_TimeUTC, "Between", [{e.Event_TimeUTC: start, f"{e.Event_TimeUTC}0": end}])
        else:
            add_condition(e.Event_TimeUTC, "LastDays", [{e.Event_TimeUTC: last_days, "displayValue": last_days}])

        base["rows"]["ordering"].append({"path": e.Event_TimeUTC, "sortOrder": "Desc" if descending else "Asc"})

    return base

class VaronisClient:
    def __init__(self, config):
        self._config = config
        self._token: str | None = None
        self._http = urllib3.PoolManager(ssl_context=_ssl_context())

    def authenticate(self) -> None:
        resp = self._http.request(
            "POST",
            f"{self._config.base_url}/api/authentication/api_keys/token",
            headers={
                "x-api-key": self._config.api_key,
                "varonis-integration": self._config.integration_name,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            fields={"grant_type": "varonis_custom"},
            encode_multipart=False,
        )
        if resp.status != 200:
            body = ""
            try:
                body = resp.data.decode("utf-8", errors="replace")
            except Exception:
                body = str(resp.data)
            raise AuthenticationError(f"Authentication failed (status={resp.status}) body={body}")

        try:
            token = json.loads(resp.data).get("access_token")
        except Exception as e:
            raise AuthenticationError("Authentication response parsing failed") from e
        if not token:
            raise AuthenticationError("Authentication token missing in response")
        self._token = token

    def _headers(self) -> dict[str, str]:
        if not self._token:
            self.authenticate()
        return {
            "Authorization": f"bearer {self._token}",
            "Content-Type": "application/json",
            "varonis-integration": self._config.integration_name,
        }

    def search(self, request: dict, *, max_rows: int | None = None) -> dict:
        payload = _to_search_v2_payload(request)
        resp = self._http.request(
            "POST",
            f"{self._config.base_url}/api/search/v2/search",
            headers=self._headers(),
            body=json.dumps(payload),
        )
        if resp.status != 200:
            body = ""
            try:
                body = resp.data.decode("utf-8", errors="replace")
            except Exception:
                body = str(resp.data)
            raise ApiRequestError(f"Search creation failed (status={resp.status}) body={body}")

        try:
            location = json.loads(resp.data)[0]["location"]
        except Exception as e:
            raise ApiRequestError("Search creation response parsing failed") from e

        url = f"{self._config.base_url}/api/search/{location}"
        if max_rows is not None:
            if max_rows < 1:
                raise ApiRequestError("max_rows must be >= 1")
            url += f"?from=0&to={max_rows - 1}"

        while True:
            poll = self._http.request("GET", url, headers=self._headers())
            if poll.status == 200:
                try:
                    return json.loads(poll.data)
                except Exception as e:
                    raise ApiRequestError("Search results parsing failed") from e
            if poll.status >= 400:
                body = ""
                try:
                    body = poll.data.decode("utf-8", errors="replace")
                except Exception:
                    body = str(poll.data)
                raise ApiRequestError(f"Search polling failed (status={poll.status}) body={body}")

    def update_alert_status(self, alert_ids: list[str], *, status_id: int, close_reason_id: int | None = None) -> None:
        payload = {"AlertGuids": alert_ids, "StatusId": status_id, "CloseReasonId": close_reason_id}
        resp = self._http.request(
            "POST",
            f"{self._config.base_url}/api/alert/alert/SetStatusToAlerts",
            headers=self._headers(),
            body=json.dumps(payload),
        )
        if resp.status != 200:
            raise ApiRequestError(f"Alert status update failed (status={resp.status})")

    def add_alert_note(self, alert_ids: list[str], note: str) -> None:
        payload = {"AlertGuids": alert_ids, "Note": note}
        resp = self._http.request(
            "POST",
            f"{self._config.base_url}/api/alert/alert/AddNoteToAlerts",
            headers=self._headers(),
            body=json.dumps(payload),
        )
        if resp.status != 200:
            raise ApiRequestError(f"Add note failed (status={resp.status})")

    def get_enum(self, enum_id: int) -> list[dict[str, Any]]:
        resp = self._http.request(
            "GET",
            f"{self._config.base_url}/api/entitymodel/enum/{enum_id}",
            headers=self._headers(),
        )
        if resp.status != 200:
            raise ApiRequestError(f"Enum lookup failed (status={resp.status})")
        try:
            return json.loads(resp.data)
        except Exception as e:
            raise ApiRequestError("Enum response parsing failed") from e
