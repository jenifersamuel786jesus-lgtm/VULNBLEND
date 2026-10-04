from flask import Flask, request, render_template_string, jsonify
import sqlite3

app = Flask(__name__)

@app.get("/health")
def health():
    return jsonify({"status": "ok", "lab": True})

@app.get("/")
def home():
    return '<h1>VulnShop Lab</h1><a href="/search?q=widget">Search</a> · <a href="/profile?name=student">Profile</a>'

@app.get("/search")
def search():
    q = request.args.get("q", "")
    # Deliberately vulnerable fixture: used only inside the internal isolated lab.
    query = "SELECT name FROM products WHERE name LIKE '%" + q + "%'"
    try:
        sqlite3.connect(":memory:").execute(query)
    except Exception as exc:
        return render_template_string(f"<h2>Results for: {q}</h2><p>{exc}</p>")
    return render_template_string(f"<h2>Results for: {q}</h2><p>0 results</p>")

@app.get("/profile")
def profile():
    name = request.args.get("name", "guest")
    return f"<h2>Profile: {name}</h2>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
