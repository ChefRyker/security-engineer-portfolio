"""
sample-app/app.py
A minimal Flask app used as a SAST/DAST/container-scan target.
It intentionally avoids common vulnerabilities so scanners
demonstrate a *clean* baseline (no SQLi, no hardcoded secrets, etc.).
"""

import os
import logging
from flask import Flask, jsonify, request, abort

app = Flask(__name__)

# Structured logging — never log sensitive fields
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


@app.route("/health")
def health():
    """Health-check endpoint for load balancers and CI readiness probes."""
    return jsonify({"status": "ok"}), 200


@app.route("/api/items", methods=["GET"])
def list_items():
    """Return a static list — replace with a parameterised DB query."""
    items = [
        {"id": 1, "name": "Widget A"},
        {"id": 2, "name": "Widget B"},
    ]
    logger.info("list_items called by %s", request.remote_addr)
    return jsonify(items), 200


@app.route("/api/items/<int:item_id>", methods=["GET"])
def get_item(item_id: int):
    """Typed path param prevents path-traversal and injection."""
    if item_id not in (1, 2):
        abort(404)
    return jsonify({"id": item_id, "name": f"Widget {item_id}"}), 200


if __name__ == "__main__":
    # Never run debug=True in production
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=debug_mode)
