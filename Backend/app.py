# app.py
import json
import logging
import asyncio
import firewall

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from stream import StreamEngine
from features import extract_zeek_features
from model import load_model, save_model, predict_with_model
from suricata_reader import stream_suricata_alerts
from mac_monitor import mac_table, start
from threat_scoring import calculate_threat_score
from alert_dedup import is_duplicate
from anomaly_model import detect_anomaly

from collections import defaultdict
from time import time
from collections import deque


FILES_LOG = Path("/home/retro/AEPS/data/zeek/zeek_logs/files.log")

# store recent alerts for correlation
CORRELATION_WINDOW = 5  # seconds
recent_alerts = defaultdict(list)

ICMP_WINDOW = 5          # seconds
ICMP_PKT_THRESHOLD = 20 # packets
icmp_tracker = defaultdict(list)

alert_confirm_tracker =defaultdict(list)
ALERT_CONFIRM_WINDOW=5
ALERT_CONFIRM_THRESHOLD=3

dns_tracker=defaultdict(list)
DNS_WINDOW=5
DNS_THRESHOLD=150

UDP_WINDOW = 5
UDP_PKT_THRESHOLD = 100
udp_tracker = defaultdict(list)

SPOOF_WINDOW = 60  # seconds
ip_identity = {}   # ip -> {mac, last_seen}


ATTACK_WINDOW = 10   # seconds
ATTACK_THRESHOLD = 20
attack_tracker = defaultdict(list)


LOG_DIR = "/home/retro/AEPS/data/zeek/zeek_logs"   # adjust if different
MODEL_PATH = Path("/home/retro/AEPS/backend/model.pkl")

app = FastAPI(title="AEPS Backend")
start()
print("[MAC] ARP sniffer started")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

engine = StreamEngine(LOG_DIR)
clf = load_model(MODEL_PATH)  # may be None

# Simple human-friendly rules (explainable)
SENSITIVE_PORTS = {22, 23, 3389, 445, 1433}



def rule_classify(rec):

    try:
        svc = (rec.get("service") or "").lower()
        proto = (rec.get("proto") or "").lower()
        dport = int(rec.get("dport") or 0)
        dur = float(rec.get("duration") or 0)
        ob = float(rec.get("orig_bytes") or 0)
        rb = float(rec.get("resp_bytes") or 0)
        opk = int(rec.get("orig_pkts") or 0)
        state = rec.get("conn_state") or ""

    except Exception:
        return ("Low", "Unclassified")

    # Data exfiltration
    if rb > 10000000:
        return ("High", "Data Exfiltration")

    # Port scan
    if state in ("S0", "REJ") and opk > 10:
        return ("High", "Port Scan")

    # Brute force attempts
    if dport in (22, 23, 3389, 445) and state in ("S0", "REJ"):
        return ("High", "Brute Force Attempt")

    # DNS abuse
    if svc == "dns" and opk > 20:
        return ("Medium", "DNS Abuse")

    # Web scanning
    if svc == "http" and state == "S0":
        return ("Medium", "Web Scan")

    # UDP flood
    if proto == "udp" and opk > 100:
        return ("High", "UDP Flood")

    # ICMP flood
    if proto == "icmp" and opk > 50:
        return ("High", "ICMP Flood")

    return ("Low", "Normal Traffic")

def get_latest_file_event():
    if not FILES_LOG.exists():
        return None

    with open(FILES_LOG, "r", errors="ignore") as f:
        lines = f.readlines()

    for line in reversed(lines):
        if line.startswith("#"):
            continue

        parts = line.strip().split("\t")
        if len(parts) < 23:
            continue

        sha256 = parts[22]
        if sha256 == "-" or sha256 == "":
            continue

        return {
            "ts": float(parts[0]),
            "src": parts[3],
            "dst": parts[5],
            "mime": parts[10],
            "sha256": sha256
        }

    return None

def update_device(dev):
    devices[dev["ip"]] = {
        "ip": dev["ip"],
        "mac": dev["mac"],
        "host": dev["host"],
        "last_seen": dev["ts"]
    }

def record_alert(src, dst, engine, attack_type, severity, ts):

    key = (src, dst)

    recent_alerts[key].append({
        "src": src,
        "dst": dst,
        "engine": engine,
        "attack_type": attack_type,
        "severity": severity,
        "ts": ts
    })

def correlate_alerts(src, dst, now):

    zeek_hit = False
    suricata_hit = False
    suricata_name = None

    key = (src, dst)

    alerts = recent_alerts.get(key, [])

    for a in alerts:

        if abs(now - a["ts"]) <= CORRELATION_WINDOW:

            if a["engine"] == "zeek":
                zeek_hit = True

            if a["engine"] == "suricata":
                suricata_hit = True
                suricata_name = a["attack_type"]

    if zeek_hit and suricata_hit:
        return True, suricata_name

    return False, None


@app.on_event("startup")
def start_sniffers():
    start()   # ✅ CORRECT


@app.get("/")
def root():
    return {"status": "AEPS Backend Running", "model_loaded": clf is not None}


@app.get("/train")
def train():
    """Train model using available logs (calls extract_zeek_features)."""
    df = extract_zeek_features(LOG_DIR)
    if df is None or df.shape[0] == 0:
        return {"trained": False, "reason": "no rows returned by feature extractor"}
    save_model(df, MODEL_PATH)
    # reload
    global clf
    clf = load_model(MODEL_PATH)
    return {"trained": True, "rows": int(len(df))}

@app.post("/firewall/enable")
async def enable_firewall():
    firewall.enable_auto_block()
    return {"status": "Firewall auto-block enabled"}


@app.post("/firewall/disable")
async def disable_firewall():
    firewall.disable_auto_block()
    return {"status": "Firewall auto-block disabled"}


@app.post("/firewall/blocked")
async def blocked_ips():
    return firewall.get_blocked_ips()

@app.websocket("/stream")
async def stream(ws: WebSocket):

    await ws.accept()
    print("WebSocket client connected")

    asyncio.create_task(suricata_task(ws))

    loop = asyncio.get_running_loop()
    gen = engine.stream_lines()

    try:

        while True:

            line = await loop.run_in_executor(None, next, gen)

            print("ZEKE LINE:", line[:120])

            rec = engine.line_to_record(line)

            if rec is None:
                continue

            if not isinstance(rec, dict):
                try:
                    rec = dict(rec)
                except:
                    continue

            now = time()

            severity, attack_type = rule_classify(rec)

            if severity in ("Medium", "High"):
                record_alert(
                    src=rec.get("src"),
                    dst=rec.get("dst"),
                    engine="zeek",
                    attack_type=attack_type,
                    severity=severity,
                    ts=now
                )

            src = rec.get("src")
            dst = rec.get("dst")
            proto = rec.get("proto")

            key = (src, dst, proto)

            # ---------------- ICMP Flood ----------------
            if proto == "icmp":

                icmp_tracker[key].append(now)
                icmp_tracker[key] = [
                    t for t in icmp_tracker[key]
                    if now - t < ICMP_WINDOW
                ]

                if len(icmp_tracker[key]) >= ICMP_PKT_THRESHOLD:
                    severity = "High"
                    attack_type = "ICMP Flood Detected"

            # ---------------- UDP Flood ----------------
            if proto == "udp":

                udp_tracker[key].append(now)
                udp_tracker[key] = [
                    t for t in udp_tracker[key]
                    if now - t < UDP_WINDOW
                ]

                if len(udp_tracker[key]) >= UDP_PKT_THRESHOLD:
                    severity = "High"
                    attack_type = "UDP Flood Detected"

            # ---------------- DNS Abuse  ----------------
            if rec.get("service") == "dns" and dst in ("8.8.8.8","1.1.1.1"):
                pass

                if rec.get("service") == "dns":

                    dns_key = (src, dst)

                    dns_tracker[dns_key].append(now)

                    dns_tracker[dns_key] = [
                        t for t in dns_tracker[dns_key]
                        if now - t < DNS_WINDOW
                    ]

                    # trigger only if extremely high DNS rate
                    if len(dns_tracker[dns_key]) >= DNS_THRESHOLD:
                        severity = "Medium"
                        attack_type = "DNS Flood / Abuse"

            attack_tracker[key].append(now)

            attack_tracker[key] = [
                t for t in attack_tracker[key]
                if now - t < ATTACK_WINDOW
            ]

            if len(attack_tracker[key]) >= ATTACK_THRESHOLD:
                severity = "High"

                if attack_type == "Normal Traffic" and proto == "tcp" and float(rec.get("orig_pkts") or 0) > 100:
                    attack_type = "Network Scan Activity"

            # ---------------- ML Detection ----------------

            ml_verdict = None

            if clf is not None:

                try:

                    ml_verdict = predict_with_model(clf, rec)

                    if ml_verdict:
                        print("ML:", ml_verdict)

                    if ml_verdict and ml_verdict.get("label") == "THREAT":

                        prob = ml_verdict.get("prob", 0)

                        if prob >= 0.8:
                            severity = "High"
                        elif prob >= 0.5:
                            severity = "Medium"

                        if ml_verdict.get("type"):
                            attack_type = ml_verdict["type"]

                        if severity == "High":
                            attack_type = f"{attack_type} (ML + Signature)"

                except Exception as e:
                    print("ML ERROR:", e)

            # ---------------- Anomaly ----------------

            anomaly = detect_anomaly(rec)

            if anomaly:
                severity = "Medium"
                attack_type = "Anomalous Traffic Pattern"

            # ---------------- Suricata Correlation ----------------

            correlated, sig_name = correlate_alerts(
                src,
                dst,
                now
            )

            if correlated:
                severity = "High"
                attack_type = f"{attack_type} (Confirmed by Suricata: {sig_name})"

            # ---------------- MAC / Spoof Detection ----------------

            spoof_detected = False
            spoof_old_mac = None
            spoof_new_mac = None

            mac_info = mac_table.get(src)

            if mac_info and src:

                current_mac = mac_info.get("mac")

                if current_mac:

                    prev = ip_identity.get(src)

                    if prev:

                        if (
                            prev["mac"] != current_mac
                            and (now - prev["last_seen"]) <= SPOOF_WINDOW
                        ):

                            spoof_detected = True
                            spoof_old_mac = prev["mac"]
                            spoof_new_mac = current_mac

                            severity = "High"
                            attack_type = f"IP Spoofing Detected ({spoof_old_mac} → {spoof_new_mac})"

                    ip_identity[src] = {
                        "mac": current_mac,
                        "last_seen": now
                    }

            threat_score = calculate_threat_score(
                severity,
                ml_verdict,
                attack_type
            )
            # ---------------- Alert Stability Filter ----------------

            confirm_key = (src, attack_type)

            alert_confirm_tracker[confirm_key].append(now)

            alert_confirm_tracker[confirm_key] = [
                t for t in alert_confirm_tracker[confirm_key]
                if now - t < ALERT_CONFIRM_WINDOW
            ]

            # downgrade severity if alert not stable
            if len(alert_confirm_tracker[confirm_key]) < ALERT_CONFIRM_THRESHOLD:
                if severity == "High":
                    severity = "Medium"
            payload = {

                "ts": rec.get("ts"),
                "src": src,
                "sport": rec.get("sport"),
                "dst": dst,
                "dport": rec.get("dport"),
                "proto": proto,
                "service": rec.get("service"),
                "duration": rec.get("duration"),
                "orig_bytes": rec.get("orig_bytes"),
                "resp_bytes": rec.get("resp_bytes"),
                "conn_state": rec.get("conn_state"),
                "orig_pkts": rec.get("orig_pkts"),
                "resp_pkts": rec.get("resp_pkts"),
                "severity": severity,
                "attack_type": attack_type,
                "threat_score": threat_score,
                "ml": ml_verdict,

                "mac": mac_info.get("mac") if mac_info else None,
                "mac_last_seen": mac_info.get("last_seen") if mac_info else None,

                "ip_spoofing": spoof_detected,
                "old_mac": spoof_old_mac,
                "new_mac": spoof_new_mac
            }

            # ---------------- Firewall Blocking ----------------
            
            print("DEBUG FIREWALL CHECK:",
                    "enabled=", firewall.is_enabled(),
                    "src=", src,
                    "severity=", severity,
                    "attack=", attack_type)

            if firewall.is_enabled() and src and severity == "High":
                print("[AUTO BLOCK] High severity:", src)
                firewall.block_ip(src, "High severity attack")

            elif "scan" in attack_type.lower():
                print("[AUTO BLOCK] Scan detected:", src)
                firewall.block_ip(src, "Port scan detected")

            elif "flood" in attack_type.lower():
                print("[AUTO BLOCK] Flood detected:", src)
                firewall.block_ip(src, "Flood attack detected")

            # ---------------- Send Normal Traffic ----------------

            if not is_duplicate(src, dst, attack_type):
                await ws.send_text(json.dumps(payload))

            # ---------------- Malware File Detection ----------------

            file_evt = get_latest_file_event()

            if file_evt:
                try:
                    # If the event is already a dictionary
                    if isinstance(file_evt, dict):
                        malware_payload = file_evt

                    # If it is a tuple/list from Zeek files.log
                    elif isinstance(file_evt, (tuple, list)) and len(file_evt) >= 5:
                        malware_payload = {
                            "ts": file_evt[0],
                            "src": file_evt[1],
                            "dst": file_evt[2],
                            "severity": "High",
                            "attack_type": "Malware File Detected",
                            "file_hash": file_evt[3],
                            "mime": file_evt[4],
                            "source": "zeek-files"
                        }

                    else:
                        malware_payload = None

                    if malware_payload:
                        await ws.send_text(json.dumps(malware_payload))

                except Exception as e:
                    print("Malware event error:", e)

    except Exception as e:

        print("WebSocket error:", e)

    finally:

        await ws.close()


async def suricata_task(ws):
    loop = asyncio.get_running_loop()
    gen = stream_suricata_alerts()

    while True:
        alert = await loop.run_in_executor(None, next, gen)

        payload = {
            "ts": alert.get("timestamp"),
            "src": alert.get("src_ip"),
            "dst": alert.get("dest_ip"),
            "proto": alert.get("proto"),
            "severity": "High",
            "attack_type": alert["alert"]["signature"],
            "source": "suricata"
        }

        try:
            await ws.send_text(json.dumps(payload))
        except RuntimeError:
            break





