from flask import Flask, render_template, request
from db import init_db, save_query, get_user_queries, load_enrichment_data
from breach_checker import check_leaklookup, check_hibp_password, check_intelx

app = Flask(__name__, instance_relative_config=True)

# Initialize DBs on startup
with app.app_context():
    init_db()
    load_enrichment_data() # Load the Kaggle CSV into memory

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    search_type = "leaklookup" # Default

    if request.method == "POST":
        identifier = request.form["identifier"].strip()
        search_type = request.form.get("search_type", "leaklookup")

        # Route to the correct checker based on user's choice
        if search_type == "leaklookup":
            results = check_leaklookup(identifier)
        elif search_type == "hibp_password":
            results = check_hibp_password(identifier)
        elif search_type == "intelx":
            results = check_intelx(identifier)
        
        # Standardize results for the template
        if results:
            results["search_type"] = search_type
            # If an error occurred, format it for display
            if results.get("error"):
                results["breached"] = True
                results["sources"] = [{"name": "Error", "description": results["error"], "date": "N/A", "compromised_data": []}]
        
        # Save the query to our local history DB
        save_query(identifier, search_type, results)

    history = get_user_queries(limit=5)
    return render_template("index.html", results=results, history=history)

if __name__ == "__main__":
    app.run(debug=True)