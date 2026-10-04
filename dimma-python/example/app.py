import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, request, jsonify
from flask_wtf.csrf import generate_csrf
from dimma.engine import DimmaEngine

app = Flask(__name__)

dimma = DimmaEngine(os.path.join(os.path.dirname(__file__), "security.dimma"))
dimma.protect(app)


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/csrf-token")
def csrf_token():
    return jsonify(csrfToken=generate_csrf())


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    return jsonify(message=f"Login recebido para {data.get('username')}")


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    try:
        # SEGURANCA: o hash NUNCA deve ser devolvido ao cliente -- numa
        # app real, guarde-o na base de dados (ex: coluna
        # "password_hash") e responda apenas com sucesso/insucesso.
        dimma.hash_password(data.get("password", ""))
        return jsonify(success=True)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400


if __name__ == "__main__":
    app.run(port=5000)
