import re
from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json

app = Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per hour", "2000 per day"])
key = ""

@app.errorhandler(400)
def error400(error):
    return jsonify({"message": "400 Bad Request"}), 400

@app.errorhandler(403)
def error403(error):
    return jsonify({"message": "403 Forbidden"}), 403

@app.errorhandler(404)
def error404(error):
    return jsonify({"message": "404 Not Found"}), 404

@app.errorhandler(405)
def error405(error):
    return jsonify({"message": "405 Method Not Allowed"}), 405

@app.errorhandler(429)
def ratelimited(error):
    return jsonify({"message": "You are being ratelimted from using Proxy Exploits API. Ratelimit is at 100 requests per hour."}), 429

@app.errorhandler(500)
def error500(error):
    return jsonify({"message": "500 Internal Server Error"}), 500

@app.route("/")
def index():
    return jsonify({"message": "The API for Proxy exploits"}), 200

@app.route("/whitelist/<path>", methods=["GET", "POST"])
@limiter.limit("100 per hour")
def whitelist(path=None):
    paths = ["check", "add"]
    if path == None or path not in paths:
        return jsonify({"message": "Invalid Path"})
    else:
        with open("whitelisted.json") as f:
            data = json.load(f)
        if path == "check":
            return data
        elif path == "add" and request.method == "POST":
            incoming = request.get_json()
            if incoming == None:
                return jsonify({"success": False, "message": "JSON body missing"}), 400
            if request.headers.get("authorization") == None or request.headers.get("authorization") != key:
                return jsonify({"success": False, "message": "403 Forbidden"}), 403
            user_id = incoming.get("user_id")
            data["whitelisted"].append(int(user_id))
            with open('whitelisted.json', 'w') as x:
                json.dump(data, x, indent=4)
            return jsonify({"success": True})
        elif path == "add" and request.method != "POST":
            return error405(error=405)

if __name__ == "__main__":
    app.run()