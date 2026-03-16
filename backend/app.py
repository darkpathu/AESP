from flask import Flask, jsonify
from flask_cors import CORS
import time

app = Flask(__name__)
CORS(app)

# Example threat data
threats = [
    {"id": 1, "type": "ARP Spoofing", "severity": "High"},
    {"id": 2, "type": "Port Scan", "severity": "Medium"},
]

@app.route("/")
def home():
    return "AESP Backend Running"

@app.route("/threats")
def get_threats():
    return jsonify(threats)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
