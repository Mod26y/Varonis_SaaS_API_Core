class BaseMapper:
    def map(self, response: dict) -> list[dict]:
        cols = response["columns"]
        return [dict(zip(cols, row)) for row in response["rows"]]

class AlertMapper(BaseMapper):
    pass

class EventMapper(BaseMapper):
    pass

class ThreatModelMapper:
    def map(self, enum_response: list[dict]) -> list[dict]:
        return [{"id": item.get("dataField"), "name": item.get("displayField")} for item in enum_response]
