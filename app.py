import os
from flask import Flask, render_template, request, session, jsonify
from db import init_db, save_query, get_user_queries, load_enrichment_data
from breach_checker import check_leaklookup, check_hibp_password, check_intelx

app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = os.urandom(24)

# --- Initialize DBs and preload enrichment data ---
with app.app_context():
    init_db()
    load_enrichment_data()

# --------------------------
# 🧠 MAIN INDEX ROUTE
# --------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    error = None

    if request.method == "POST":
        identifier = request.form["identifier"].strip()
        search_type = request.form.get("search_type", "leaklookup")

        # --- Input validation ---
        if len(identifier) > 256:
            error = "Search term is too long (maximum 256 characters)."
            history = get_user_queries(limit=5)
            return render_template("index.html", error=error, history=history)

        # --- Route API checks ---
        if search_type == "leaklookup":
            results = check_leaklookup(identifier)
        elif search_type == "hibp_password":
            results = check_hibp_password(identifier)
        elif search_type == "intelx":
            results = check_intelx(identifier)

        # --- Handle API failures gracefully ---
        if results:
            results["search_type"] = search_type
            if results.get("error"):
                print(f"API Error Occurred: {results['error']}")
                results["breached"] = True
                results["sources"] = [{
                    "name": "Search Error",
                    "description": "The external API failed to respond. Please try again later.",
                    "date": "N/A", "compromised_data": []
                }]
            session['last_result'] = results

        # --- Save user query to DB ---
        save_query(identifier, search_type, results)

    # --- Render dashboard with history + general mitigations ---
    history = get_user_queries(limit=5)

    # 🧩 General mitigation list (display below mind map)
    general_mitigations = [
        "Use unique and complex passwords for each service.",
        "Enable multi-factor authentication (MFA) wherever possible.",
        "Regularly update software, browsers, and plugins.",
        "Be cautious when clicking unknown links or downloading attachments.",
        "Monitor accounts for unusual activity or unauthorized logins.",
        "Avoid using public Wi-Fi for sensitive transactions.",
        "Use a password manager to securely store credentials.",
        "Regularly back up critical data to offline or encrypted storage.",
        "Stay informed about current phishing and social engineering tactics.",
        "Immediately change passwords if a breach is suspected."
    ]

    return render_template(
        "index.html",
        results=results,
        history=history,
        error=error,
        general_mitigations=general_mitigations
    )

# --------------------------
# ⚙️ APP ENTRY
# --------------------------
if __name__ == "__main__":
    app.run(debug=True, ssl_context="adhoc")
