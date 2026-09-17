from flask import Flask, jsonify, request
app = Flask(__name__)

@app.get("/")
def home():
    return jsonify({
        "name": "Secured Lab Internal Target",
        "scope": "container-only",
        "endpoints": ["/", "/sqli", "/xss", "/idor", "/headers"]
    })

@app.get("/sqli")
def sqli():
    value = request.args.get("name", "")
    return jsonify({
        "challenge": "SQL injection",
        "input": value,
        "mode": "training",
        "hint": "The production app should use parameterized queries. This target returns a safe training response instead of executing supplied SQL."
    })

@app.get("/xss")
def xss():
    value = request.args.get("q", "")
    return jsonify({
        "challenge": "Cross-site scripting",
        "input": value,
        "mode": "training",
        "hint": "Check how the main application escapes user-controlled output."
    })

@app.get("/idor")
def idor():
    user_id = request.args.get("user_id", "1")
    return jsonify({
        "challenge": "Object authorization",
        "requested_id": user_id,
        "mode": "training",
        "hint": "Verify that an authenticated user cannot access another user's object."
    })

@app.get("/headers")
def headers():
    return jsonify({"message": "Compare these headers with the main application."})

app.run(host="0.0.0.0", port=8080)
