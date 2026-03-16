import json

EVE_PATH = "/var/log/suricata/eve.json"

def stream_suricata_alerts():
    with open(EVE_PATH, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    yield data
            except Exception:
                continue
