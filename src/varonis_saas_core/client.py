class VaronisClient:
    def __init__(self, config):
        self.config = config

    def search(self, request: dict, *, max_rows=None) -> dict:
        return {"columns": [], "rows": []}

    def update_alert_status(self, alert_ids, *, status_id, close_reason_id=None) -> None:
        pass

    def add_alert_note(self, alert_ids, note: str) -> None:
        pass

    def get_enum(self, enum_id: int):
        return []
