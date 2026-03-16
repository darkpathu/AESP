import numpy as np
from sklearn.ensemble import IsolationForest

model = IsolationForest(contamination=0.02, random_state=42)

trained = False

def train_anomaly_model(data):
    global trained
    model.fit(data)
    trained = True

def detect_anomaly(rec):
    if not trained:
        return False

    try:
        vec = [[
            float(rec.get("duration") or 0),
            float(rec.get("orig_bytes") or 0),
            float(rec.get("resp_bytes") or 0),
            float(rec.get("orig_pkts") or 0),
            float(rec.get("resp_pkts") or 0)
        ]]

        pred = model.predict(vec)

        return pred[0] == -1
    except:
        return False