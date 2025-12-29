import json

def json_dumps(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)
