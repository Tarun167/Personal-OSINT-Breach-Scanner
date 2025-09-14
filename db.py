import sqlite3
import pandas as pd
from flask import g

# --- Section 1: History Database (for user search history) ---
HISTORY_DATABASE = "instance/breach.db"

def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    if "db" not in g:
        g.db = sqlite3.connect(HISTORY_DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Closes the database again at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the history database schema."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL,
            search_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.commit()

def save_query(identifier, search_type, result):
    """Saves a search query and its summary to the history database."""
    db = get_db()
    summary = "✅ Safe / No Results"
    if result and result.get('breached'):
        source_count = len(result.get('sources', []))
        summary = f"⚠️ Found in {source_count} source(s)"
    
    db.execute(
        "INSERT INTO queries (identifier, search_type, summary) VALUES (?, ?, ?)",
        (identifier, search_type, summary)
    )
    db.commit()

def get_user_queries(limit=5):
    """Retrieves the most recent user queries from the history database."""
    db = get_db()
    return db.execute(
        "SELECT * FROM queries ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()


# --- Section 2: Enrichment Database (from Kaggle CSV) ---
ENRICHMENT_CSV_PATH = "instance/enrichment_breaches.csv"
enrichment_df = None # This global variable will hold your entire CSV in memory.

def load_enrichment_data():
    """
    Loads the Kaggle CSV into a global pandas DataFrame.
    This function is called only ONCE when the app starts for maximum efficiency.
    """
    global enrichment_df
    if enrichment_df is None: # Only load if it hasn't been loaded yet
        try:
            enrichment_df = pd.read_csv(ENRICHMENT_CSV_PATH, low_memory=False)
            # Pre-process the 'Entity' column for faster, case-insensitive searching
            enrichment_df['Entity_lower'] = enrichment_df['Entity'].str.lower()
            print("✅ Enrichment database (CSV) loaded into memory successfully.")
        except FileNotFoundError:
            print(f"⚠️ WARNING: Enrichment CSV not found at '{ENRICHMENT_CSV_PATH}'. Enrichment will be disabled.")
            enrichment_df = pd.DataFrame() # Create an empty DataFrame to prevent errors

def get_enrichment_data(breach_name: str):
    """
    Searches the in-memory DataFrame for extra data about a breach.
    This is much faster than connecting to a file for every search.
    """
    global enrichment_df
    if enrichment_df.empty:
        return {}

    # Search the pre-processed lowercase column for a partial match
    search_name = breach_name.lower()
    result = enrichment_df[enrichment_df['Entity_lower'].str.contains(search_name, na=False)]
    
    if not result.empty:
        # Return the first match as a dictionary, replacing any missing values (NaN) with "N/A"
        return result.iloc[0].fillna("N/A").to_dict()
    return {}