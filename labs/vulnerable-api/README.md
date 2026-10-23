# ShopKart Lab API

An intentionally vulnerable API for practising authorization and business-logic
testing with Strix. Single file, standard library only, no install step.

```bash
python labs/vulnerable-api/server.py --port 8080
curl -s http://127.0.0.1:8080/health
```

Point Strix at the bundled contract:

```bash
strix -n -t ./labs/vulnerable-api/openapi.json -t http://127.0.0.1:8080 --scan-mode quick \
  --max-budget 2 \
  --instruction "Seeded accounts, password Passw0rd!: victim@shopkart.test,
    attacker@shopkart.test, admin@shopkart.test. Test authorization across them."
```

## Seeded accounts

| Account | Id | Role |
| --- | --- | --- |
| `victim@shopkart.test` | 1 | user |
| `attacker@shopkart.test` | 2 | user |
| `admin@shopkart.test` | 3 | admin |

Password for all three: `Passw0rd!`

## Planted bugs

Try to find these yourself before opening `find_bugs.sh`.

| ID | Class | Where | Severity |
| --- | --- | --- | --- |
| B1 | BOLA / IDOR | `GET /api/v1/invoices/{id}` | High |
| B2 | Mass assignment → admin | `PATCH /api/v1/users/me` with `role` | Critical |
| B3 | Broken function-level auth | `GET /api/v1/admin/users` | High |
| B4 | JWT `alg:none` forgery | any authenticated route | Critical |
| B5 | Excessive data exposure | `GET /api/v1/users/{id}` | Medium–High |
| B6 | SQL injection (`UNION`) | `GET /api/v1/search?q=` | High |
| B7 | OTP brute force, no lockout | `POST /api/v1/auth/verify-otp` | High |
| B8 | Business logic, negative amount | `POST /api/v1/wallet/transfer` | Critical |
| B9 | Unsalted MD5 password storage | `users.password` | Medium (chain) |

## Helper endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/_lab/otp?email=` | Reveals a seeded OTP so you can watch the flow without brute forcing. A real target would not have this. |
| `POST /api/v1/_lab/reset` | Restores the seeded state |

## Reference reproduction

```bash
labs/vulnerable-api/find_bugs.sh http://127.0.0.1:8080
```

`tests/test_vulnerable_api_lab.py` asserts every bug above is still exploitable.

> [!WARNING]
> Local use only. Never expose this server to an untrusted network.
