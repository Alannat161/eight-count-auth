"""Tests for Eight Count Auth."""

import sqlite3
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from app import create_app, initialize_database


@pytest.fixture
def app(tmp_path):
    """Give each test an isolated database."""
    application = create_app(tmp_path / "test_keys.db")
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def database_rows(app):
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            "SELECT kid, key, exp FROM keys ORDER BY kid"
        ).fetchall()


def verify_token(app, token, verify_exp=True):
    """Verify the actual signature using the matching stored public key."""
    header = jwt.get_unverified_header(token)
    row = next(row for row in database_rows(app) if str(row["kid"]) == header["kid"])
    private_key = serialization.load_pem_private_key(row["key"], password=None)
    return jwt.decode(
        token,
        private_key.public_key(),
        algorithms=["RS256"],
        options={"verify_exp": verify_exp},
    )


def test_database_contains_expired_and_valid_keys(app):
    rows = database_rows(app)
    now = int(time.time())

    assert any(row["exp"] <= now for row in rows)
    assert any(row["exp"] >= now + 3600 for row in rows)
    assert len({row["kid"] for row in rows}) == len(rows)

    for row in rows:
        assert isinstance(row["key"], bytes)
        assert b"BEGIN RSA PRIVATE KEY" in row["key"]


def test_restart_preserves_existing_keys(app):
    before = [tuple(row) for row in database_rows(app)]
    restarted = create_app(app.config["DATABASE"])
    after = [tuple(row) for row in database_rows(restarted)]

    assert before == after


def test_auth_without_body(app, client):
    response = client.post("/auth")

    assert response.status_code == 200
    token = response.get_data(as_text=True)
    claims = verify_token(app, token)

    assert claims["sub"] == "userABC"
    assert claims["exp"] > time.time()
    assert jwt.get_unverified_header(token)["alg"] == "RS256"


@pytest.mark.parametrize(
    "query",
    ["?expired", "?expired=true", "?expired=false"],
)
def test_expired_parameter_uses_expired_key(app, client, query):
    response = client.post("/auth" + query)

    assert response.status_code == 200
    token = response.get_data(as_text=True)
    claims = verify_token(app, token, verify_exp=False)

    assert claims["exp"] <= time.time()

    with pytest.raises(jwt.ExpiredSignatureError):
        verify_token(app, token)

    expired_kid = jwt.get_unverified_header(token)["kid"]
    published = client.get("/.well-known/jwks.json").get_json()["keys"]
    assert expired_kid not in {key["kid"] for key in published}


def test_basic_auth(app, client):
    response = client.post(
        "/auth",
        headers={"Authorization": "Basic dXNlckFCQzpwYXNzd29yZDEyMw=="},
    )

    assert response.status_code == 200
    assert verify_token(app, response.get_data(as_text=True))["sub"] == "userABC"


def test_json_auth(app, client):
    response = client.post(
        "/auth",
        json={"username": "alanna", "password": "password123"},
    )

    assert response.status_code == 200
    assert verify_token(app, response.get_data(as_text=True))["sub"] == "alanna"


@pytest.mark.parametrize("body", [{}, {"username": ""}, {"username": 123}, []])
def test_json_without_valid_username(app, client, body):
    response = client.post("/auth", json=body)

    assert response.status_code == 200
    assert verify_token(app, response.get_data(as_text=True))["sub"] == "userABC"


def test_sql_like_username_is_only_data(app, client):
    username = "student'; DROP TABLE keys; --"
    before = [tuple(row) for row in database_rows(app)]

    response = client.post("/auth", json={"username": username})

    assert response.status_code == 200
    assert verify_token(app, response.get_data(as_text=True))["sub"] == username
    assert before == [tuple(row) for row in database_rows(app)]


def test_jwks_contains_all_valid_public_keys(app, client):
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    keys = response.get_json()["keys"]
    expected = {
        str(row["kid"]) for row in database_rows(app) if row["exp"] > time.time()
    }

    assert {key["kid"] for key in keys} == expected

    for key in keys:
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        assert "n" in key and "e" in key
        assert not {"d", "p", "q", "dp", "dq", "qi"} & key.keys()


def test_published_jwk_verifies_token(client):
    token = client.post("/auth").get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    keys = client.get("/.well-known/jwks.json").get_json()["keys"]
    matching = next(key for key in keys if key["kid"] == header["kid"])

    public_key = jwt.PyJWK.from_dict(matching).key
    claims = jwt.decode(token, public_key, algorithms=["RS256"])

    assert claims["sub"] == "userABC"


def test_jwks_returns_multiple_valid_keys(app, client):
    original = next(row for row in database_rows(app) if row["exp"] > time.time())
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (original["key"], original["exp"]),
        )

    keys = client.get("/.well-known/jwks.json").get_json()["keys"]
    assert len(keys) == 2
    assert len({key["kid"] for key in keys}) == 2


@pytest.mark.parametrize("expired", [False, True])
def test_missing_signing_key_returns_503(app, client, expired):
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.execute("DELETE FROM keys")

    path = "/auth?expired" if expired else "/auth"
    response = client.post(path)

    assert response.status_code == 503
    assert "error" in response.get_json()


def test_empty_database_returns_empty_jwks(app, client):
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.execute("DELETE FROM keys")

    assert client.get("/.well-known/jwks.json").get_json() == {"keys": []}


def test_initialization_replaces_missing_valid_key(app):
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.execute(
            "UPDATE keys SET exp = ?",
            (int(time.time()) - 60,),
        )

    initialize_database(app.config["DATABASE"])

    assert any(row["exp"] > time.time() for row in database_rows(app))


def test_wrong_http_methods_are_rejected(client):
    assert client.get("/auth").status_code == 405
    assert client.post("/.well-known/jwks.json").status_code == 405
    assert client.get("/missing").status_code == 404
