class VaronisConfig:
    def __init__(self, base_url: str, api_key: str, integration_name: str = "Custom Integration"):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.integration_name = integration_name
