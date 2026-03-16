# features.py
import os
import pandas as pd


def _parse_conn_line(l: str):
    parts = l.split("\t")

    def safe_float(i):
        try:
            return float(parts[i])
        except:
            return 0.0

    def safe_str(i):
        try:
            return parts[i] if parts[i] not in ("", "-") else ""
        except:
            return ""

    return {
        "duration": safe_float(8),
        "orig_bytes": safe_float(9),
        "resp_bytes": safe_float(10),
        "orig_pkts": safe_float(12),
        "resp_pkts": safe_float(13),
        "proto": safe_str(6),
        "service": safe_str(7),
    }



def extract_zeek_features(zeek_dir: str):
    path = os.path.join(zeek_dir, "conn.log")
    if not os.path.exists(path):
        return None

    rows = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("#"):
                continue
            r = _parse_conn_line(line.strip())
            rows.append(r)

    df = pd.DataFrame(rows)

    # 🔥 BETTER LABELING (LEVEL 2)
    df["label"] = (
        (df["orig_pkts"] > 20) |
        (df["resp_pkts"] > 20) |
        (df["orig_bytes"] > 50000) |
        (df["resp_bytes"] > 50000) |
        (df["duration"] > 60)
    ).astype(int)


    df["proto_tcp"] = (df["proto"].str.lower() == "tcp").astype(int)
    df["proto_udp"] = (df["proto"].str.lower() == "udp").astype(int)

    features = [
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
        "proto_tcp",
        "proto_udp"
    ]

    return df[features + ["label"]].dropna()

    def label_from_behavior(row):
        if row["pkts_per_sec"] > 100:
            return 1
        if row["bytes_per_sec"] > 500000:
            return 1
        if row["total_pkts"] > 50:
            return 1
        return 0

    df["label"] = df.apply(label_from_behavior, axis=1)

    features = [
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
        "total_bytes",
        "total_pkts",
        "bytes_per_sec",
        "pkts_per_sec",
        "proto_tcp",
        "proto_udp",
        "proto_icmp",
    ]

    df = df[features + ["label"]]

    return df
