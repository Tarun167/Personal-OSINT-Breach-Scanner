import os
import requests
import hashlib
import time
import json
import html
from dotenv import load_dotenv
from db import get_enrichment_data

# Load environment variables
load_dotenv()
LEAKLOOKUP_API_KEY = os.getenv("LEAKLOOKUP_API_KEY")
INTELX_API_KEY = os.getenv("INTELX_API_KEY")

# --- NEW HELPER FUNCTION: Centralized Risk Classification ---
def _classify_breach_risk(data_classes: list) -> dict:
    """
    Analyzes a list of compromised data types and returns a risk classification.
    """
    text_to_analyze = "".join(data_classes).lower()
    sensitive_data_found = []
    risk_level = "Low"

    # Check for high-risk keywords first
    if "password" in text_to_analyze: sensitive_data_found.append("Passwords")
    if "financial" in text_to_analyze or "credit card" in text_to_analyze: sensitive_data_found.append("Financial Data")
    if "ssn" in text_to_analyze: sensitive_data_found.append("Govt. IDs (SSN)")
    
    # If no high-risk data found, check for medium-risk
    if not sensitive_data_found:
        if "email" in text_to_analyze: sensitive_data_found.append("Emails")
        if "phone" in text_to_analyze: sensitive_data_found.append("Phone Numbers")
        if "name" in text_to_analyze: sensitive_data_found.append("Full Names")

    # Determine final risk and create the classification string
    if "Passwords" in sensitive_data_found or "Financial Data" in sensitive_data_found or "Govt. IDs (SSN)" in sensitive_data_found:
        risk_level = "High"
    elif sensitive_data_found:
        risk_level = "Medium"
    
    classification_text = f"{risk_level}-Risk Data ({', '.join(sensitive_data_found)})" if sensitive_data_found else "Low-Risk Data"

    return {"risk_level": risk_level, "breach_classification": classification_text}


# --- Parsers: These convert raw API data to our Standard Object ---

def _parse_hibp_password(api_data, password):
    """Parses the HIBP Pwned Passwords response."""
    if api_data.get("breached"):
        count = api_data.get('count', 0)
        return [{
            "name": f"Password Found {count:,} Times",
            "date": "N/A",
            "description": html.escape("This password has appeared in a data breach. It is highly insecure and should not be used anywhere."),
            "data_classes": ["Password"],
            "source_api": "HIBP"
        }]
    return []

def _parse_leaklookup(api_data):
    """Parses Leak-Lookup response, enriches it, sanitizes it, and classifies the risk."""
    sources = []
    breaches = api_data.get("result") or api_data.get("message", {})
    for breach_name, _ in breaches.items():
        clean_name = breach_name.replace("_", " ").title()
        enrichment = get_enrichment_data(clean_name)
        
        data_classes = []
        if 'Records lost' in enrichment and enrichment['Records lost'] > 0:
            try:
                records = int(enrichment['Records lost'])
                data_classes.append(f"Records Lost: {records:,}")
            except (ValueError, TypeError): pass
        if 'SECTOR' in enrichment: data_classes.append(f"Sector: {enrichment['SECTOR']}")
        if 'Method' in enrichment: data_classes.append(f"Method: {enrichment['Method']}")
        
        # Call the new helper function
        classification = _classify_breach_risk(data_classes)

        standard_object = {
            "name": html.escape(clean_name),
            "date": html.escape(str(enrichment.get('Date', "N/A"))),
            "description": html.escape(str(enrichment.get('Summary', "Details not available in local DB."))),
            "data_classes": [html.escape(str(dc)) for dc in data_classes],
            "source_api": "Leak-Lookup",
            "risk_level": classification["risk_level"],
            "breach_classification": classification["breach_classification"]
        }
        sources.append(standard_object)
    return sources

def _parse_intelx(api_data):
    """Parses IntelligenceX response, filters, sanitizes, and classifies the risk."""
    sources = []
    RELEVANT_TYPES = ["Document", "Text", "Text File", "Database File", "Paste", "Domain"]

    records = api_data.get('records', [])
    for record in records:
        if not isinstance(record, dict) or record.get('typeh') not in RELEVANT_TYPES:
            continue

        name = record.get('name', '')
        if '/' in name: name = name.split('/')[-1]
        if not name or name.strip() == "": name = f"Item in {record.get('bucketh', 'Unknown')}"

        description = record.get('description', '').strip()
        if not description: description = f"Source: {record.get('bucketh', 'N/A')}"
        
        data_classes = [f"Type: {record.get('typeh')}"]
        if record.get('date'): data_classes.append(f"Date: {record.get('date')[:10]}")
        if record.get('size', 0) > 0: data_classes.append(f"Size: {record.get('size', 0) / 1024:.2f} KB")
        if record.get('systemid'): data_classes.append(f"IntelX ID: {record.get('systemid')[:18]}...")
        
        # Call the new helper function
        classification = _classify_breach_risk(data_classes)

        standard_object = {
            "name": html.escape(name),
            "date": html.escape(record.get('date', 'N/A')),
            "description": html.escape(description),
            "data_classes": [html.escape(dc) for dc in data_classes],
            "source_api": "IntelligenceX",
            "risk_level": classification["risk_level"],
            "breach_classification": classification["breach_classification"]
        }
        sources.append(standard_object)
    return sources

# --- API Callers: These remain unchanged ---
def check_hibp_password(password):
    try:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if res.status_code != 200:
            return {"error": f"HIBP API failed ({res.status_code})"}

        match = next((line for line in res.text.splitlines() if line.startswith(suffix)), None)

        if match:
            _, count_str = match.split(":")
            count = int(count_str.strip())
        else:
            count = 0

        return {
            "breached": count > 0,
            "count": count,
            "hash_prefix": prefix,
        }

    except Exception as e:
        return {"error": str(e)}

def check_leaklookup(identifier: str):
    """High-level function for Leak-Lookup check."""
    if not LEAKLOOKUP_API_KEY:
        return {"error": "LEAKLOOKUP_API_KEY not configured."}
    
    search_type = "username"
    if "@" in identifier: search_type = "email_address"
    
    url = "https://leak-lookup.com/api/search"
    params = {"key": LEAKLOOKUP_API_KEY, "type": search_type, "query": identifier}
    headers = {"User-Agent": "Personal-OSINT-Dashboard"}
    
    try:
        response = requests.post(url, data=params, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data.get("error") == "true": return {"error": data.get("message", "Unknown error")}
            if not data.get("result") and not data.get("message"):
                 return {"identifier": identifier, "breached": False, "sources": []}
            final_sources = _parse_leaklookup(data)
            return {"identifier": identifier, "breached": bool(final_sources), "sources": final_sources}
        else:
            return {"error": f"Server returned status {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network Error: {e}"}

def check_intelx(query: str):
    """High-level function for IntelligenceX check."""
    if not INTELX_API_KEY:
        return {"error": "INTELX_API_KEY not configured."}
    
    search_url = "https://free.intelx.io/intelligent/search"
    result_url = "https://free.intelx.io/intelligent/search/result"
    headers = {"x-key": INTELX_API_KEY, "User-Agent": "Personal-OSINT-Dashboard", "Content-Type": "application/json"}
    search_body = {"term": query, "maxresults": 15, "media": 0, "sort": 2, "terminate": []}
    
    try:
        search_response = requests.post(search_url, headers=headers, data=json.dumps(search_body))
        if search_response.status_code != 200:
            return {"error": f"IntelX search initiation failed. Status: {search_response.status_code}"}
        search_id = search_response.json().get('id')
        if not search_id:
            return {"error": "IntelX did not return a search ID."}
        time.sleep(5)
        result_params = {"id": search_id, "limit": 15}
        results_response = requests.get(result_url, headers=headers, params=result_params)
        if results_response.status_code != 200:
            return {"error": f"Failed to fetch IntelX results. Status: {results_response.status_code}"}
        
        records = results_response.json()
        final_sources = _parse_intelx(records)
        return {"identifier": query, "breached": bool(final_sources), "sources": final_sources}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error with IntelligenceX: {e}"}