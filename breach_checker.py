import os , requests, hashlib, time, json
from dotenv import load_dotenv
from db import get_enrichment_data
# Import our enrichment function

# Load environment variables
load_dotenv()
LEAKLOOKUP_API_KEY = os.getenv("LEAKLOOKUP_API_KEY")
INTELX_API_KEY = os.getenv("INTELX_API_KEY")

# --- FUNCTION 1: HIBP Pwned Password Checker ---
def check_hibp_password(password: str):
    """Checks a password against HIBP's Pwned Passwords API using k-Anonymity."""
    try:
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        response = requests.get(url, headers={"User-Agent": "Personal-OSINT-Dashboard"})

        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return {"identifier": password, "breached": True, "count": int(count)}
            return {"identifier": password, "breached": False, "count": 0}
        else:
            return {"error": f"HIBP API returned status {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network Error: {e}"}

# --- FUNCTION 2: Leak-Lookup Identifier Checker (with Enrichment) ---
# In breach_checker.py

def check_leaklookup(identifier: str):
    """
    Checks an identifier (email/user) against the Leak-Lookup API.
    This version is updated according to the official API documentation.
    """
    if not LEAKLOOKUP_API_KEY:
        return {"error": "LEAKLOOKUP_API_KEY is not configured in the .env file."}

    # Determine the search type based on the identifier format
    # This is the key fix, as "auto" is not a valid type in the docs.
    search_type = "username"
    if "@" in identifier:
        search_type = "email_address"
    
    # API endpoint and parameters
    url = "https://leak-lookup.com/api/search"
    params = {
        "key": LEAKLOOKUP_API_KEY,
        "type": search_type,
        "query": identifier
    }
    
    # The docs require a User-Agent, so we will include one.
    headers = {
        "User-Agent": "Personal-OSINT-Dashboard"
    }

    try:
        response = requests.post(url, data=params, headers=headers)

        if response.status_code == 200:
            data = response.json()
            
            # The API returns an 'error' key with the value 'true' on failure.
            if data.get("error") == "true":
                # The 'message' will contain a specific reason from the docs,
                # like "REQUEST LIMIT REACHED" or "INVALID API KEY".
                return {"error": data.get("message", "An unknown API error occurred.")}
            
            # A successful response with no results has an empty "message" or "result"
            if not data.get("result") and not data.get("message"):
                return {"identifier": identifier, "breached": False, "sources": []}
            
            # Successful response with breaches found
            breaches = data.get("result") or data.get("message", {})
            sources = []
            for breach_name, details in breaches.items():
                clean_name = breach_name.replace("_", " ").title()
                
                # --- ENRICHMENT STEP ---
                enrichment = get_enrichment_data(clean_name)
                
                source_info = {
                    "name": clean_name,
                    "description": enrichment.get('Summary', "Details not available in local DB."),
                    "date": enrichment.get('Date', "N/A"),
                    "compromised_data": []
                }

                if 'Records lost' in enrichment and enrichment['Records lost'] > 0:
                    records = int(enrichment['Records lost'])
                    source_info["compromised_data"].append(f"Records Lost: {records:,}")
                if 'SECTOR' in enrichment:
                    source_info["compromised_data"].append(f"Sector: {enrichment['SECTOR']}")
                if 'Method' in enrichment:
                    source_info["compromised_data"].append(f"Method: {enrichment['Method']}")
                
                sources.append(source_info)

            return {"identifier": identifier, "breached": True, "sources": sources}
        else:
            return {"error": f"The API server responded with an unexpected HTTP status: {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"A network error occurred: {e}"}


# --- FUNCTION 3: IntelligenceX Advanced Search (Definitive Version) ---
def check_intelx(query: str):
    """Performs a real search using the IntelligenceX API and handles non-uniform responses."""
    if not INTELX_API_KEY:
        return {"error": "INTELX_API_KEY not configured in the .env file."}

    # --- UPDATED: Using the correct 'free' endpoint you discovered ---
    search_url = "https://free.intelx.io/intelligent/search"
    result_url = "https://free.intelx.io/intelligent/search/result"
    
    headers = {
        "x-key": INTELX_API_KEY,
        "User-Agent": "Personal-OSINT-Dashboard",
        "Content-Type": "application/json"
    }
    search_body = { "term": query, "maxresults": 15, "media": 0, "sort": 2, "terminate": [] }

    try:
        # Step 1: Initiate the search
        search_response = requests.post(search_url, headers=headers, data=json.dumps(search_body))
        if search_response.status_code != 200:
            return {"error": f"IntelX search initiation failed. Status: {search_response.status_code} {search_response.text}"}
        
        search_id = search_response.json().get('id')
        if not search_id:
            return {"error": "IntelligenceX did not return a search ID."}

        # Step 2: Wait for results
        time.sleep(5) # Increased wait time slightly for better results

        # Step 3: Fetch the results
        result_params = {"id": search_id, "limit": 15}
        results_response = requests.get(result_url, headers=headers, params=result_params)
        if results_response.status_code != 200:
            return {"error": f"Failed to fetch IntelX results. Status: {results_response.status_code} {results_response.text}"}

        records = results_response.json().get('records', [])
        if not records:
            return {"identifier": query, "breached": False, "sources": []}
        
        # --- Step 4: NEW - Robustly format the non-uniform results ---
        sources = []
        media_type_map = { 0: "Text", 1: "Picture", 2: "Video", 3: "Audio", 4: "Document", 8: "Archive" }
        
        for record in records:
            # Defensively check if the record is a dictionary
            if not isinstance(record, dict):
                continue

            # Create a guaranteed, meaningful title for the node
            name = record.get('name')
            if not name:
                bucket = record.get('bucket', 'Unknown Source')
                # Take the first 8 characters of the system ID for a unique name
                system_id_short = record.get('systemid', 'xxxxxx')[:8]
                name = f"Result in {bucket} ({system_id_short})"

            # Dynamically build the list of details, only showing data that actually exists
            compromised_data = []
            if record.get('date'):
                compromised_data.append(f"Date: {record.get('date')}")
            
            media_type = media_type_map.get(record.get('media'), 'Unknown')
            compromised_data.append(f"Type: {media_type}")
            
            if record.get('size', 0) > 0:
                size_kb = record.get('size', 0) / 1024
                compromised_data.append(f"Size: {size_kb:.2f} KB")

            source_info = {
                "name": name,
                "description": f"Source: {record.get('bucket', 'N/A')}",
                "date": record.get('date', 'N/A'),
                "compromised_data": compromised_data
            }
            sources.append(source_info)

        return {"identifier": query, "breached": True, "sources": sources}

    except requests.exceptions.RequestException as e:
        return {"error": f"A network error occurred with IntelligenceX: {e}"}