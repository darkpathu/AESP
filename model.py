# model.py
import pickle
from pathlib import Path
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

def save_model(df, path: Path):
    X = df.drop(columns=["label"])
    y = df["label"]
    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X, y)
    with open(path, "wb") as f:
        pickle.dump({"clf": clf, "columns": list(X.columns)}, f)
    return clf

def load_model(path: Path):
    try:
        with open(path, "rb") as f:
            obj = pickle.load(f)
            return obj
    except Exception:
        return None

def predict_with_model(obj, rec: dict):
    """
    obj: dict loaded from model.pkl
    rec: parsed Zeek record
    Returns: {"label": "THREAT"/"NORMAL", "prob": float}
    """
    if obj is None:
        return None

    clf = obj.get("clf")
    cols = obj.get("columns")

    if clf is None or cols is None:
        return None

    try:
        # 🔹 Build feature vector EXACTLY like training
        feature_map = {
            "duration": float(rec.get("duration") or 0),
            "orig_bytes": float(rec.get("orig_bytes") or 0),
            "resp_bytes": float(rec.get("resp_bytes") or 0),
            "orig_pkts": float(rec.get("orig_pkts") or 0),
            "resp_pkts": float(rec.get("resp_pkts") or 0),
            "proto_tcp": 1 if (rec.get("proto", "").lower() == "tcp") else 0,
            "proto_udp": 1 if (rec.get("proto", "").lower() == "udp") else 0,
        }

        X = [[feature_map.get(c, 0) for c in cols]]

        proba = clf.predict_proba(X)[0]
        classes = list(clf.classes_)

        if 1 in classes:
            prob_threat = proba[classes.index(1)]
        else:
            prob_threat = max(proba)

        label = "THREAT" if prob_threat >= 0.5 else "NORMAL"

        return {
            "label": label,
            "prob": float(prob_threat)
        }

    except Exception as e:
        print("ML INTERNAL ERROR:", e)
        return None


