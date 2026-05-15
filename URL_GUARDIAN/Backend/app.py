from flask import Flask, request, jsonify
from flask_cors import CORS
from hybrid import hybrid_check

app = Flask(__name__)
CORS(app)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    url = data.get("url")
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    # This calls the logic in your hybrid.py file
    result = hybrid_check(url)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)