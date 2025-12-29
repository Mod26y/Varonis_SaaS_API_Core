from __future__ import annotations
import json
import ssl
import urllib3
from typing import Any
from .errors import AuthenticationError, ApiRequestError

def _ssl_context() -> ssl.SSLContext:
    # Tighten in your environment if possible.
    ctx = ssl._create_unverified_context()
    ctx.load_default_certs()
    return ctx

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
            },
            fields={"grant_type": "varonis_custom"},
        )
        if resp.status != 200:
            raise AuthenticationError(f"Authentication failed (status={resp.status})")
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
        resp = self._http.request(
            "POST",
            f"{self._config.base_url}/api/search/v2/search",
            headers=self._headers(),
            body=json.dumps(request),
        )
        if resp.status != 200:
            raise ApiRequestError(f"Search creation failed (status={resp.status})")

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
                raise ApiRequestError(f"Search polling failed (status={poll.status})")

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
