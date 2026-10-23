"""Intentionally vulnerable API used as a practice target for Strix.

Every control in this file is broken on purpose so that a learner can practise
the bug classes that pay in web/API bug bounties: BOLA/IDOR, broken
function-level authorization, mass assignment, JWT `alg: none` forgery,
excessive data exposure, SQL injection, OTP brute force and negative-amount
business logic.

It is a single file with no third-party dependencies so it runs anywhere the
Strix sandbox runs, including inside CI tests.

Run it locally only::

    python labs/vulnerable-api/server.py --port 8080

Then point Strix at it::

    strix --target ./labs/vulnerable-api/openapi.json --target http://127.0.0.1:8080

Do not expose this server to a network you do not control.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse


if TYPE_CHECKING:
    from collections.abc import Callable

APP_VERSION = "2.3.1"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
SECRET = "shopkart-dev-secret"  # deliberate lab value, not a real credential
PASSWORD = "Passw0rd!"  # seeded lab password
ALLOWED_PATCH_FIELDS = {"name", "phone", "role", "balance", "email"}
MASS_ASSIGNMENT_FIELD = "role"


# --------------------------------------------------------------------------- errors
class ApiError(Exception):
    """HTTP error carrying the status code the lab should return."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


# --------------------------------------------------------------------------- tokens
def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_token(user_id: int, email: str, role: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 86400,
    }
    signing_input = (
        f"{_b64encode(json.dumps(header).encode())}.{_b64encode(json.dumps(payload).encode())}"
    )
    signature = hmac.new(SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64encode(signature)}"


def _decode_token(token: str) -> dict[str, Any]:
    """Decode a token, honouring ``alg: none`` - the planted JWT weakness."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ApiError(401, "malformed token")
    try:
        header = json.loads(_b64decode(parts[0]))
        payload = json.loads(_b64decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ApiError(401, "malformed token") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ApiError(401, "malformed token")
    if header.get("alg") != "none":
        expected = hmac.new(
            SECRET.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256
        ).digest()
        try:
            actual = _b64decode(parts[2])
        except ValueError as exc:
            raise ApiError(401, "bad signature") from exc
        if not hmac.compare_digest(expected, actual):
            raise ApiError(401, "bad signature")
    return payload


def _hash_password(raw: str) -> str:
    # Unsalted MD5 on purpose: realistic legacy storage and an offline-crack chain.
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


# --------------------------------------------------------------------------- state
class LabState:
    """In-memory database plus the lock that guards it."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.conn.executescript(
                """
                DROP TABLE IF EXISTS users;
                DROP TABLE IF EXISTS invoices;
                CREATE TABLE users(
                    id INTEGER PRIMARY KEY,
                    email TEXT UNIQUE,
                    name TEXT,
                    password TEXT,
                    role TEXT DEFAULT 'user',
                    balance REAL DEFAULT 1000.0,
                    phone TEXT,
                    aadhaar TEXT,
                    otp TEXT
                );
                CREATE TABLE invoices(
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    number TEXT,
                    amount REAL,
                    currency TEXT,
                    card_last4 TEXT,
                    address TEXT
                );
                """
            )
            digest = _hash_password(PASSWORD)
            rows = [
                (
                    1,
                    "victim@shopkart.test",
                    "Victim Kumar",
                    digest,
                    "user",
                    5400.0,
                    "+91-9000000001",
                    "XXXX-XXXX-4321",
                    "0000",
                ),
                (
                    2,
                    "attacker@shopkart.test",
                    "Attacker Raja",
                    digest,
                    "user",
                    1000.0,
                    "+91-9000000002",
                    "XXXX-XXXX-9999",
                    "1111",
                ),
                (
                    3,
                    "admin@shopkart.test",
                    "Admin",
                    digest,
                    "admin",
                    0.0,
                    "+91-9000000003",
                    "XXXX-XXXX-0000",
                    "2222",
                ),
            ]
            self.conn.executemany(
                "INSERT INTO users(id, email, name, password, role, balance, phone, aadhaar, otp)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self.conn.execute(
                "INSERT INTO invoices(user_id, number, amount, currency, card_last4, address)"
                " VALUES(1, 'INV-2026-0001', 14999.0, 'INR', '4321',"
                " '12 MG Road, Bengaluru 560001')"
            )
            self.conn.execute(
                "INSERT INTO invoices(user_id, number, amount, currency, card_last4, address)"
                " VALUES(2, 'INV-2026-0002', 2499.0, 'INR', '9999',"
                " '4B Anna Salai, Chennai 600002')"
            )
            self.conn.commit()

    # -- helpers ---------------------------------------------------------
    def user_by_id(self, user_id: int) -> sqlite3.Row:
        with self.lock:
            row = self.conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if row is None:
            raise ApiError(404, "not found")
        return row

    def user_by_email(self, email: str) -> sqlite3.Row:
        with self.lock:
            row = self.conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if row is None:
            raise ApiError(404, "not found")
        return row

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self.lock:
            cursor = self.conn.execute(sql, params)
            self.conn.commit()
            return cursor.fetchall()


@dataclass(slots=True)
class Request:
    state: LabState
    query: dict[str, list[str]]
    body: dict[str, Any]
    headers: dict[str, str]
    match: re.Match[str]

    def require_user(self) -> sqlite3.Row:
        raw = self.headers.get("authorization", "")
        if not raw.lower().startswith("bearer "):
            raise ApiError(401, "missing token")
        payload = _decode_token(raw.split(" ", 1)[1].strip())
        subject = payload.get("sub")
        if not isinstance(subject, int):
            raise ApiError(401, "bad subject")
        return self.state.user_by_id(subject)


# --------------------------------------------------------------------------- handlers
def _health(req: Request) -> tuple[int, Any]:  # noqa: ARG001 - route signature
    return 200, {"status": "ok", "version": APP_VERSION}


def _login(req: Request) -> tuple[int, Any]:
    email = str(req.body.get("email", ""))
    password = str(req.body.get("password", ""))
    row = req.state.user_by_email(email)
    if row["password"] != _hash_password(password):
        raise ApiError(401, "invalid credentials")
    return 200, {"token": issue_token(row["id"], row["email"], row["role"])}


def _register(req: Request) -> tuple[int, Any]:
    email = str(req.body.get("email", ""))
    if not email:
        raise ApiError(400, "email required")
    name = str(req.body.get("name", ""))
    otp = f"{secrets.randbelow(10000):04d}"
    req.state.execute(
        "INSERT INTO users(email, name, password, otp) VALUES(?,?,?,?)",
        (email, name, _hash_password(str(req.body.get("password", ""))), otp),
    )
    row = req.state.user_by_email(email)
    return 201, {"token": issue_token(row["id"], row["email"], row["role"])}


def _verify_otp(req: Request) -> tuple[int, Any]:
    # No attempt counter, no lockout: a 4-digit OTP is brute-forceable.
    row = req.state.user_by_email(str(req.body.get("email", "")))
    if row["otp"] and str(req.body.get("otp", "")) == row["otp"]:
        return 200, {"token": issue_token(row["id"], row["email"], row["role"])}
    raise ApiError(400, "wrong otp")


def _me(req: Request) -> tuple[int, Any]:
    user = req.require_user()
    return 200, {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "balance": user["balance"],
    }


def _update_me(req: Request) -> tuple[int, Any]:
    # Mass assignment: the body is bound straight onto the row.
    user = req.require_user()
    fields = {key: value for key, value in req.body.items() if key in ALLOWED_PATCH_FIELDS}
    if fields:
        assignments = ", ".join(f"{key}=?" for key in fields)
        req.state.execute(
            f"UPDATE users SET {assignments} WHERE id=?",  # planted mass assignment
            (*fields.values(), user["id"]),
        )
    row = req.state.user_by_id(user["id"])
    return 200, {"id": row["id"], "role": row["role"], "balance": row["balance"]}


def _get_user(req: Request) -> tuple[int, Any]:
    # Excessive data exposure: any authenticated user reads any row, hash included.
    req.require_user()
    row = req.state.user_by_id(int(req.match["user_id"]))
    return 200, dict(row)


def _list_invoices(req: Request) -> tuple[int, Any]:
    user = req.require_user()
    rows = req.state.execute("SELECT * FROM invoices WHERE user_id=?", (user["id"],))
    return 200, [dict(row) for row in rows]


def _get_invoice(req: Request) -> tuple[int, Any]:
    # BOLA: authenticates, never authorises.
    req.require_user()
    rows = req.state.execute("SELECT * FROM invoices WHERE id=?", (int(req.match["invoice_id"]),))
    if not rows:
        raise ApiError(404, "not found")
    return 200, dict(rows[0])


def _admin_users(req: Request) -> tuple[int, Any]:
    # Broken function-level authorization: no role check at all.
    req.require_user()
    rows = req.state.execute("SELECT id, email, name, role, balance, aadhaar FROM users")
    return 200, [dict(row) for row in rows]


def _search(req: Request) -> tuple[int, Any]:
    term = req.query.get("q", [""])[0]
    # SQL injection: user input concatenated straight into the statement.
    sql = f"SELECT id, email, name FROM users WHERE email LIKE '%{term}%' OR name LIKE '%{term}%'"
    try:
        rows = req.state.execute(sql)
    except sqlite3.Error as exc:
        return 500, {"error": str(exc), "query": sql}
    return 200, [dict(row) for row in rows]


def _transfer(req: Request) -> tuple[int, Any]:
    # Business logic: a negative amount mints balance for the sender.
    user = req.require_user()
    amount = float(req.body.get("amount", 0))
    recipient = req.state.user_by_email(str(req.body.get("to_email", "")))
    req.state.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, user["id"]))
    req.state.execute(
        "UPDATE users SET balance = balance + ? WHERE id=?", (amount, recipient["id"])
    )
    row = req.state.user_by_id(user["id"])
    return 200, {"sender_balance": row["balance"], "amount": amount}


def _lab_reset(req: Request) -> tuple[int, Any]:
    req.state.reset()
    return 200, {"reset": True}


def _lab_otp(req: Request) -> tuple[int, Any]:
    # Lab-only helper so a learner can watch the OTP flow without brute forcing.
    row = req.state.user_by_email(req.query.get("email", [""])[0])
    return 200, {"email": row["email"], "otp": row["otp"]}


ROUTES: list[tuple[str, re.Pattern[str], Callable[[Request], tuple[int, Any]]]] = [
    ("GET", re.compile(r"^/health$"), _health),
    ("POST", re.compile(r"^/api/v1/auth/login$"), _login),
    ("POST", re.compile(r"^/api/v1/auth/register$"), _register),
    ("POST", re.compile(r"^/api/v1/auth/verify-otp$"), _verify_otp),
    ("GET", re.compile(r"^/api/v1/users/me$"), _me),
    ("PATCH", re.compile(r"^/api/v1/users/me$"), _update_me),
    ("GET", re.compile(r"^/api/v1/users/(?P<user_id>\d+)$"), _get_user),
    ("GET", re.compile(r"^/api/v1/invoices$"), _list_invoices),
    ("GET", re.compile(r"^/api/v1/invoices/(?P<invoice_id>\d+)$"), _get_invoice),
    ("GET", re.compile(r"^/api/v1/admin/users$"), _admin_users),
    ("GET", re.compile(r"^/api/v1/search$"), _search),
    ("POST", re.compile(r"^/api/v1/wallet/transfer$"), _transfer),
    ("POST", re.compile(r"^/api/v1/_lab/reset$"), _lab_reset),
    ("GET", re.compile(r"^/api/v1/_lab/otp$"), _lab_otp),
]


# --------------------------------------------------------------------------- http
class LabHandler(BaseHTTPRequestHandler):
    server_version = f"ShopKartLab/{APP_VERSION}"
    state: LabState

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def log_message(self, *_args: object) -> None:
        return

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        for route_method, pattern, handler in ROUTES:
            match = pattern.match(parsed.path)
            if route_method != method or match is None:
                continue
            request = Request(
                state=self.state,
                query=parse_qs(parsed.query),
                body=self._read_body(),
                headers={key.lower(): value for key, value in self.headers.items()},
                match=match,
            )
            self._respond(handler, request)
            return
        self._send(404, {"error": "no such route"})

    def _respond(self, handler: Callable[[Request], tuple[int, Any]], request: Request) -> None:
        try:
            status, payload = handler(request)
        except ApiError as exc:
            self._send(exc.status, {"error": exc.message})
            return
        except (sqlite3.Error, ValueError) as exc:
            self._send(500, {"error": str(exc)})
            return
        self._send(status, payload)

    def _send(self, status: int, payload: Any) -> None:
        raw = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def build_server(host: str = DEFAULT_HOST, port: int = 0) -> ThreadingHTTPServer:
    """Create a server bound to ``host:port``. Port 0 picks a free port."""
    state = LabState()
    handler = type("BoundLabHandler", (LabHandler,), {"state": state})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Intentionally vulnerable practice API")
    parser.add_argument("--host", default=DEFAULT_HOST, help="bind address (default: loopback)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="bind port")
    args = parser.parse_args(argv)
    server = build_server(args.host, args.port)
    host, port = server.server_address[0], server.server_address[1]
    print(f"vulnerable lab API on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
