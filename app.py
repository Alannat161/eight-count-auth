"""Eight Count Auth: SQLite-backed JWKS server.

Alanna Thompson — CSCE 3550, Project 2
"""

import base64
import sqlite3
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

DATABASE = "totally_not_my_privateKeys.db"


def generate_private_key():
    """Serialize a new RSA private key as PKCS1 PEM bytes."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def initialize_database(database):
    """Create the table and ensure expired and valid keys are available."""
    now = int(time.time())

    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )

        expired = connection.execute(
            "SELECT kid FROM keys WHERE exp <= ? LIMIT 1",
            (now,),
        ).fetchone()

        # Ensure a key remains valid for at least another hour at startup.
        valid = connection.execute(
            "SELECT kid FROM keys WHERE exp >= ? LIMIT 1",
            (now + 3600,),
        ).fetchone()

        if expired is None:
            connection.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (generate_private_key(), now - 3600),
            )

        if valid is None:
            connection.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (generate_private_key(), now + 7200),
            )


def read_keys(database, expired=False):
    """Read matching keys using bound SQL parameters."""
    now = int(time.time())

    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row

        if expired:
            rows = connection.execute(
                """
                SELECT kid, key, exp FROM keys
                WHERE exp <= ? ORDER BY exp DESC, kid DESC
                """,
                (now,),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT kid, key, exp FROM keys
                WHERE exp > ? ORDER BY exp DESC, kid DESC
                """,
                (now,),
            ).fetchall()

    return rows


def encode_integer(value):
    """Encode an RSA integer in the base64url format required by JWK."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_jwk(row):
    """Derive public information without exposing private key material."""
    private_key = serialization.load_pem_private_key(
        row["key"],
        password=None,
    )
    numbers = private_key.public_key().public_numbers()

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": str(row["kid"]),
        "n": encode_integer(numbers.n),
        "e": encode_integer(numbers.e),
    }


def create_app(database=DATABASE):
    """Create an application with a configurable database for testing."""
    app = Flask(__name__)
    app.config["DATABASE"] = str(Path(database).resolve())
    initialize_database(app.config["DATABASE"])

    @app.post("/auth")
    def authenticate():
        """Mock authentication and issue a signed JWT."""
        expired = "expired" in request.args
        rows = read_keys(app.config["DATABASE"], expired=expired)

        if not rows:
            return jsonify(error="No matching signing key available"), 503

        row = rows[0]
        now = int(time.time())

        # Accept Basic auth, a JSON body, or no body for the test clients.
        username = "userABC"
        credentials = request.authorization

        if credentials and credentials.type.lower() == "basic":
            username = credentials.username or username
        else:
            body = request.get_json(silent=True)
            if isinstance(body, dict):
                supplied_username = body.get("username")
                if isinstance(supplied_username, str) and supplied_username:
                    username = supplied_username

        # The expired route must return a JWT with an expired timestamp.
        expires = row["exp"] if expired else min(now + 3600, row["exp"])
        issued = min(now, expires - 1)

        token = jwt.encode(
            {"sub": username, "iat": issued, "exp": expires},
            row["key"],
            algorithm="RS256",
            headers={"kid": str(row["kid"])},
        )
        return app.response_class(token, mimetype="text/plain")

    @app.get("/.well-known/jwks.json")
    def jwks():
        """Publish public keys for all unexpired database entries."""
        rows = read_keys(app.config["DATABASE"])
        return jsonify(keys=[public_jwk(row) for row in rows])

    return app


if __name__ == "__main__":
    application = create_app()
    print("Eight Count Auth | Alanna Thompson | CSCE 3550")
    print("SQLite-backed JWKS server listening on port 8080")
    application.run(host="127.0.0.1", port=8080, debug=False)
