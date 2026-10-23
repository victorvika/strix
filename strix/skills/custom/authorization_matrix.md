---
name: authorization-matrix
description: Systematic object-level and function-level authorization testing - build the actor-by-object-by-verb matrix, enumerate reachable object ids, and prove cross-account access without false positives
---

# Authorization Matrix

Authorization bugs are the highest-yield class on any API, and they fail for the
same reason every time: the handler proves **who** the caller is and never proves
**what the caller may touch**. The test is mechanical once the matrix exists, so
this skill is about building the matrix and refusing to submit until it is
complete.

## The matrix

Three dimensions. Fill every reachable cell, or mark it explicitly skipped:

- **Actors** — anonymous, user A, user B (same role, different tenant), a
  second role (support/staff/agent), an admin. Two accounts of the same role are
  the minimum; a second role is where vertical findings live.
- **Objects** — every resource the API exposes: `invoice`, `order`, `wallet`,
  `document`, `export`, `report`, `attachment`, `member`, `invitation`.
- **Verbs** — `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, plus bulk/batch routes
  and export/download routes that are easy to forget.

Expected outcome per cell is fixed: an actor may succeed only on objects it
owns, with the function its role permits. Any deviation is a candidate.

| Actor | Object | Verb | Expected | Observed |
|---|---|---|---|---|
| anon | any | GET | 401 | |
| A | A's object | GET | 200 | baseline |
| A | B's object | GET | 403/404 | |
| A | B's object | PATCH | 403/404 | |
| A | B's object | DELETE | 403/404 | |
| A | admin function | ANY | 403 | |
| staff | A's object | GET | 200 | |

Record the baseline first: a 200 on the actor's *own* object is what proves the
request itself is well-formed. Without a baseline, a 200 on another account's
object may simply mean the endpoint ignores parameters.

## Enumerating object ids

You cannot test what you cannot address. Sources, cheapest first:

1. **List endpoints** — `GET /objects` of the attacker account returns the
   attacker's ids and reveals the id format.
2. **Create responses** — a created resource often returns a sibling's id in
   relationships (`owner`, `parent`, `related_ids`).
3. **Relation traversal** — `GET /orders/{id}/invoices` may return another
   tenant's identifiers if the parent check is missing.
4. **Search/filter endpoints** — filters that accept ids (`?user_id=`,
   `?account=`) are frequently unauthorized even when the detail route is not.
5. **Format analysis** — sequential integers, base64 of integers, hashids,
   UUIDv1 (timestamp/MAC ordering), UUIDv4 (unguessable, so focus on
   *relationships* rather than guessing).

Never brute-force identifiers against production. Two concrete ids are enough
proof; state enumerability as an impact note rather than demonstrating it at
scale.

## Where the check is usually missing

- **Detail routes** that trust the path id (`/invoices/{id}`) while the list
  route is correctly scoped.
- **Nested routes** — `/users/{id}/documents` checks the parent for listing but
  not for item retrieval.
- **Write verbs on read-authorized objects** — `GET` scoped, `PATCH`/`DELETE`
  not.
- **Bulk operations** — `POST /batch`, `POST /bulk-delete`,
  `POST /export` that trust a client-supplied id list.
- **Alternative identifiers** — the endpoint validates the primary key but also
  accepts `number`, `slug`, `external_id`, or `email` as a lookup, unchecked.
- **Parameter expansion** — `?fields=owner.email`, `?expand=account`,
  `?include=members` pulling objects across the tenant boundary.
- **Body/query/header precedence** — the token gives actor A, but the body
  carries `user_id: B` and the handler trusts the body.
- **Cached responses** — a response cache keyed without the tenant id serves
  another account's data for a short window.

## Bypass techniques worth trying

- Method override: `X-HTTP-Method-Override`, `_method=DELETE`, `POST` with
  `X-HTTP-Method`.
- Path normalization: trailing slash, `//`, `%2f`, `..;/`, case variation,
  unicode normalization on the route prefix.
- Content-type switching: `application/json` → `application/x-www-form-urlencoded`
  or multipart, which sometimes lands on a different parser than the authz
  middleware covers.
- Duplicate keys: two `id` parameters, or `{"id": A, "id": B}` — parsers disagree
  on which wins.
- Array wrapping: `{"id": [A, B]}` where the server takes the first element for
  the check and the last for the query.
- Header confusion: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`,
  `X-Forwarded-For` used as a trusted principal.

## Validation and false positives

Reject the candidate unless all of the following hold:

1. **Fresh session**, newly issued token, request replayed by hand.
2. The response contains data or a state change that belongs to the **other**
   actor, verified by a field you control (email, phone suffix, a marker value
   you set).
3. Read findings are not an **empty/placeholder** response. Inspect the body;
   `200` with `{"items":[],"error":null}` is not disclosure.
4. Write findings **persist**: re-read as both actors after the write.
5. The endpoint is not intentionally public. Check for a documented public
   share/token route before reporting an anonymous `200`.
6. No other explanation fits: not a cached copy of the actor's own record, not a
   shared demo tenant, not a seeded sample object visible to everyone.

Impact grading that triage accepts:

- cross-account **read** of non-sensitive metadata — low/medium,
- cross-account **read** of PII, financial, or health data — high,
- cross-account **write or delete** — high/critical,
- **vertical** escalation to an administrative capability — critical,
- **tenant-wide** exposure combined with sequential ids — critical, state the
  count.

## Coverage bookkeeping

Emit a ledger entry for every cell: `actor, method, path, object_owner,
expected, observed, verdict, evidence_ref`. The ledger is the deliverable as much
as the findings are — it prevents duplicate work across agents, lets the report
answer "did you test the delete path?", and shows which of the three dimensions
is under-tested. When a run is cut short by budget, report the untested cells
instead of implying full coverage.
