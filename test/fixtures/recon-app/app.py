import requests
from flask import Flask

app = Flask(__name__)


@app.route("/health")
def health():
    requests.get("https://example.com/health")
    return "ok"
