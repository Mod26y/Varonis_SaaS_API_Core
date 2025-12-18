class BaseMapper:
    def map(self, response: dict) -> list[dict]:
        cols = response.get("columns", [])
        return [dict(zip(cols, row)) for row in response.get("rows", [])]

class AlertMapper(BaseMapper):
    pass

class EventMapper(BaseMapper):
    pass

class ThreatModelMapper:
    def map(self, enum_response: list[dict]) -> list[dict]:
        return [{"id": e.get("dataField"), "name": e.get("displayField")} for e in enum_response]
