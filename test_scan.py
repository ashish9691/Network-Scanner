from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/scan", methods=["GET", "POST"])
def scan_network():
    if request.method == "POST":
        body = request.get_json(force=True)
        return jsonify({"msg": "POST request received", "data": body})
    else:
        ip = request.args.get("ip", "none")
        return jsonify({"msg": "GET request received", "ip": ip})

if __name__ == "__main__":
    print(">>> Running scan_test.py from:", __file__)
    app.run(host="127.0.0.1", port=5000, debug=True)
