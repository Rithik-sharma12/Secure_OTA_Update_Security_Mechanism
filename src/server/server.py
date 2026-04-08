from flask import Flask, send_file, jsonify
import hashlib
import os

app = Flask(__name__)

FIRMWARE_FILE = "firmware_v2.bin"

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

@app.route("/manifest")
def manifest():
    return jsonify({
        "version": "2.0.0",
        "url": "/firmware",
        "sha256": sha256_of(FIRMWARE_FILE),
        "size": os.path.getsize(FIRMWARE_FILE)
    })

@app.route("/firmware")
def firmware():
    return send_file(FIRMWARE_FILE, mimetype="application/octet-stream")

if __name__ == "__main__":
    if not os.path.exists(FIRMWARE_FILE):
        with open(FIRMWARE_FILE, "wb") as f:
            f.write(b"\xE9" + b"\x00" * 4096)
        print("Created dummy firmware: " + FIRMWARE_FILE)
    else:
        print("Using existing firmware: " + FIRMWARE_FILE)

    print("Server running at http://10.136.94.70:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
