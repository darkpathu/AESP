def calculate_threat_score(severity, ml_verdict, attack_type, source=None):
    score = 0

    # rule based severity
    if severity == "High":
        score += 40
    elif severity == "Medium":
        score += 20

    # ML probability
    if ml_verdict and ml_verdict.get("prob"):
        score += int(ml_verdict["prob"] * 30)

    # attack patterns
    if attack_type and attack_type != "Normal Traffic":
        score += 20

    # suricata alerts
    if source == "suricata":
        score += 30

    return min(score, 100)
