from datetime import datetime

def classify_breach(entry):
    """
    Classifies a breach entry based on its data classes and source.
    Returns a category tag (e.g., 'password', 'email', 'phone', etc.)
    that maps directly to mitigation categories in the DB.
    """
    classes = [c.lower() for c in entry.get("data_classes", [])]
    src = entry.get("source", "").lower()

    # Match most likely exposed element
    if "password" in classes:
        return "password"
    if "email" in classes:
        return "email"
    if "username" in classes or "user" in classes:
        return "username"
    if "full_name" in classes or "name" in classes:
        return "full_name"
    if "phone" in classes or "contact" in classes:
        return "phone"
    if "ip" in classes or "ip_address" in classes:
        return "ip_address"
    if "api" in src or any("token" in c for c in classes):
        return "token_in_repo"

    # Broader types (less common)
    if any(c in ["credit", "card", "bank"] for c in classes):
        return "card_data_exposed"
    if any(c in ["pii", "identity", "aadhar", "passport"] for c in classes):
        return "pii_in_paste"

    return "unclassified"


def compute_confidence(entry):
    """
    Computes confidence score (0.0–1.0) based on source reliability,
    breach recency, and richness of data exposed.
    """
    trust_map = {
        "haveibeenpwned": 1.0,
        "dehashed": 0.9,
        "telegram": 0.6,
        "unknown": 0.5
    }
    src = entry.get("source", "").lower()
    trust = trust_map.get(src, 0.5)

    recency = 1.0
    if entry.get("breach_date"):
        try:
            years = (datetime.now() - datetime.fromisoformat(entry["breach_date"])).days / 365
            recency = max(0, 1 - 0.2 * years)
        except Exception:
            recency = 0.8

    richness = len(entry.get("data_classes", [])) / 5
    evidence = min(1.0, 0.5 + 0.5 * richness)

    confidence = round(0.3 * trust + 0.3 * recency + 0.4 * evidence, 2)
    return confidence


def get_mitigation(tag, db):
    """
    Fetches mitigation recommendations and risk level
    from the 'mitigations' table in the SQLite DB.
    """
    q = db.execute("SELECT risk_level, mitigations FROM mitigations WHERE category=?", (tag,))
    res = q.fetchone()

    if res:
        risk_level, mitigation_text = res
        return (mitigation_text, risk_level)

    return ("Monitor accounts for suspicious activity and follow standard security hygiene.", "Low")
