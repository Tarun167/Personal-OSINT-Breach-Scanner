import os
import sqlite3
import pandas as pd
from flask import g

# --- Database Paths ---
HISTORY_DATABASE = os.path.join("instance", "breach.db")
ENRICHMENT_CSV_PATH = os.path.join("instance", "enrichment_breaches.csv")

# --- Section 1: Database Connection Management ---
def get_db():
    """Get a database connection for the current request context."""
    if "db" not in g:
        g.db = sqlite3.connect(HISTORY_DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    """Close the active database connection."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


# --- Section 2: Database Initialization ---
def init_db():
    """Initialize required tables: user queries + mitigations."""
    db = get_db()

    # Table: Search history
    db.execute("""
        CREATE TABLE IF NOT EXISTS queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL,
            search_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table: Mitigations
    db.execute("""
        CREATE TABLE IF NOT EXISTS mitigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT UNIQUE NOT NULL,
            risk_level TEXT,
            definition TEXT,
            rationale TEXT,
            mitigations TEXT,
            preventions TEXT
        )
    """)

    db.commit()
    print("✅ Database initialized with 'queries' and 'mitigations' tables.")


# --- Section 3: Search History ---
def save_query(identifier, search_type, result):
    """Save a user query and its summary."""
    db = get_db()
    summary = "✅ Safe / No Results"
    if result and result.get("breached"):
        source_count = len(result.get("sources", []))
        summary = f"⚠️ Found in {source_count} source(s)"

    db.execute(
        "INSERT INTO queries (identifier, search_type, summary) VALUES (?, ?, ?)",
        (identifier, search_type, summary)
    )
    db.commit()


def get_user_queries(limit=5):
    """Get the most recent search queries."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM queries ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return rows


# --- Section 4: Mitigation Management ---
def insert_mitigation_record(category, risk_level, definition, rationale, mitigations, preventions):
    """Insert or update mitigation data."""
    db = get_db()
    db.execute("""
        INSERT INTO mitigations (category, risk_level, definition, rationale, mitigations, preventions)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(category) DO UPDATE SET
            risk_level=excluded.risk_level,
            definition=excluded.definition,
            rationale=excluded.rationale,
            mitigations=excluded.mitigations,
            preventions=excluded.preventions
    """, (category, risk_level, definition, rationale, mitigations, preventions))
    db.commit()


def get_all_mitigations_from_db():
    """Return all mitigation records sorted alphabetically."""
    db = get_db()
    rows = db.execute("SELECT * FROM mitigations ORDER BY category ASC").fetchall()
    return [dict(row) for row in rows]


# --- Section 5: Enrichment Database (Kaggle CSV) ---
enrichment_df = None  # Cached in-memory dataframe

def load_enrichment_data():
    """Load enrichment data from CSV (if present)."""
    global enrichment_df
    if enrichment_df is None:
        try:
            enrichment_df = pd.read_csv(ENRICHMENT_CSV_PATH, low_memory=False)
            enrichment_df["Entity_lower"] = enrichment_df["Entity"].str.lower()
            print("✅ Enrichment CSV loaded successfully.")
        except FileNotFoundError:
            print(f"⚠️ WARNING: Enrichment CSV not found at '{ENRICHMENT_CSV_PATH}'.")
            enrichment_df = pd.DataFrame()


def get_enrichment_data(breach_name: str):
    """Return enrichment details for a given breach name."""
    global enrichment_df
    if enrichment_df is None or enrichment_df.empty:
        return {}

    search_name = breach_name.lower()
    result = enrichment_df[enrichment_df["Entity_lower"].str.contains(search_name, na=False)]

    if not result.empty:
        return result.iloc[0].fillna("N/A").to_dict()
    return {}
