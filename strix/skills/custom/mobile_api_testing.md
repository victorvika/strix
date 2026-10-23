---
name: mobile-api-testing
description: Test the API surface behind iOS and Android apps from captured traffic, exported specs, or backend source - authorization matrix, token handling, deep links, and attestation gaps
---

# Mobile API Testing

A mobile app is a client you cannot read and a transport you cannot trivially
intercept. The valuable target is almost never the app: it is **the API the app
talks to**, which is frequently less hardened than the web client that fronts
the same backend.

## Know what this sandbox can and cannot do

The pentest sandbox does **not** ship device tooling: there is no `adb`, no
`frida`, no `jadx`, no `apktool`, no MobSF, and no attached device. Do not claim
to have decompiled an APK, bypassed certificate pinning, or hooked a running app
from inside the sandbox — those steps happen on the user's machine, outside the
agent's reach, and inventing results from them is fabrication.

What the sandbox does have, and what it should be pointed at:

- an intercepting proxy (request/response capture and replay),
- a shell with `curl`, `jq`, and the usual HTTP tooling,
- a Python runtime for scripting multi-account and matrix tests,
- the ability to read a locally mounted decompiled source tree, a captured
  traffic archive, or an OpenAPI/Postman export.

So the input contract is one or more of:

1. **Captured traffic** — HAR export, proxy history, or raw request dumps
   recorded while the user exercised the app.
2. **An API contract** — OpenAPI/Swagger or a Postman collection, ideally with a
   base URL.
3. **Backend source** — a repository serving the mobile API, analysed
   white-box.
4. **Static-extract artefacts** — endpoint/secret lists the user produced
   offline with jadx/apktool/MobSF, supplied as files.

If none of these exist, the correct move is to ask the user for one, not to
guess endpoints.

## Building the endpoint inventory

From traffic, extract per request: method, path, query parameters, body shape,
auth headers, device headers, and app version. Then normalize:

- Collapse object identifiers into templates: `/orders/8412` → `/orders/{id}`.
  The template set is the test surface; the concrete ids are test data.
- Capture the **auth scheme** exactly as sent: bearer JWT, opaque token,
  refresh token, API key header, `X-Device-Id`, `X-App-Version`,
  `X-Platform`, signature headers.
- Note **client-supplied trust** headers. `X-Device-Id`, `X-App-Version`,
  `X-Forwarded-For`, `X-Request-Id`, and any HMAC signature header are
  candidates: if the server believes them without binding them to the session,
  the finding is usually worth more than a generic IDOR.
- Keep the **baseline response** for each endpoint — every abuse case is judged
  against it.

## Priority order for mobile APIs

1. **BOLA / IDOR** across two accounts. Mobile APIs expose object ids in
   payloads far more often than web UIs do (`user_id`, `wallet_id`,
   `device_id`, `kyc_id`), and mobile clients rarely verify ownership because
   the UI only ever shows the caller's own data.
2. **Broken function-level authorization.** Admin/staff/agent endpoints probed
   with a normal user's token. Mobile apps commonly bundle internal endpoints
   that the UI never calls.
3. **Functionality hidden from the UI.** Parameters the client never sends but
   the server accepts: `role`, `is_verified`, `kyc_status`, `limit`,
   `plan`, `credit_limit`, `is_agent`. Echo the response to confirm the write.
4. **Token lifecycle.** Long-lived tokens with no rotation, refresh tokens that
   survive logout, tokens valid after password change, predictable or unsigned
   JWT (`alg: none`), and tokens accepted from a different device without
   re-authentication.
5. **OTP and device binding.** No attempt cap, OTP reusable, OTP bound to the
   phone number but not the request, `device_id` bypassable by omitting the
   header.
6. **Excessive data exposure.** Mobile payloads often carry the full database
   row — hashes, internal flags, other users' identifiers, KYC documents,
   `api_token` fields — because the client is trusted to ignore them.
7. **Deep links and app links.** A deep link that resolves to an authenticated
   action (payment confirmation, password reset, invite acceptance) without
   verifying the caller is often a one-request account-takeover primitive. Test
   the *API* the deep link drives, not the link handler itself.
8. **Attestation gaps.** Play Integrity / App Attest / device binding that is
   absent, client-asserted, or replayable. Prove by replaying a captured
   assertion or simply omitting it and observing the request succeed.
9. **File and media endpoints.** Upload/download ids are object references;
   signed URL expiry and scope are frequently unchecked.
10. **WebView and bridge misuse.** Only reachable with in-app context; treat as
    a hypothesis to confirm against the API or the supplied source, never as an
    assumed result.

## Two-account matrix

Authorization findings need a real second actor. Build the matrix explicitly:

| Actor | Object | Verb | Expected | Observed |
|---|---|---|---|---|
| A (user) | A's order | GET | 200 | 200 baseline |
| A (user) | B's order | GET | 403/404 | 200 → finding |
| A (user) | A's order | PATCH | 200 | 200 baseline |
| A (user) | B's order | PATCH | 403/404 | 200 + persisted → finding |
| A (user) | admin endpoint | GET | 403 | 200 → finding |

Reuse the captured request verbatim, changing only the token. Do not "clean up"
headers — device headers and app-version headers can be part of the
authorization decision, and removing them produces false negatives.

## Bypass and edge techniques

- **Identifier formats.** Sequential integers enumerate; UUIDv1 leaks timestamps
  and MAC-derived ordering; base64 of a small integer is trivially decoded;
  hashids with a leaked salt are reversible. Try the *sibling* object's id
  format rather than guessing.
- **Parameter precedence.** Send the object id simultaneously in the path,
  query, body, and header, each pointing at a different account. Whichever wins
  reveals which input the server trusts — that is the bug.
- **Method and verb tampering.** `X-HTTP-Method-Override`, `_method` body
  field, `POST` with `X-HTTP-Method: PUT`, trailing slash, `..;/`, and case
  variation on route prefixes.
- **Version drift.** The app may call `/v3/...` while `/v2/...` and `/v1/...`
  remain served. Test the older handler with the newer token.
- **Batch/bulk endpoints.** Mobile clients batch aggressively; `POST /batch`
  with mixed ownership often bypasses per-object checks that work fine on
  single-object routes.
- **Rate limiting.** Mobile APIs frequently key limits on device id or IP
  headers rather than the account. Rotating a client-supplied header is not a
  finding by itself — the finding is the completed attack it enables.

## Validation rules

- Reproduce with a **fresh login** on both accounts; mobile tokens are often
  short-lived and a stale token produces misleading 401/403 noise.
- Confirm the data belongs to the other account — compare a field you know
  (`email`, `phone` last digits) rather than trusting a 200.
- For write findings, **re-read the object** afterwards (or check the other
  account's view) to prove persistence. A 200 response is not persistence.
- For device-binding and attestation claims, prove the negative case too: the
  same request with the header removed or the assertion replayed.
- Redact third-party PII in reports; use your own two accounts throughout.

## Reporting notes specific to mobile

Include, because triagers ask for them:

- app version/build number and platform used to capture traffic,
- endpoint and method with the raw request block,
- whether the issue also reproduces from the web client (scope is often split),
- for token-storage and pinning claims: the device/OS version and the exact
  observation, or nothing at all — those claims cannot be confirmed from a
  proxy capture and are routinely rejected when asserted without evidence.
