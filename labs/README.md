# Labs

Practice targets that ship with the repository. They are intentionally
vulnerable and exist so that techniques can be reproduced and verified without
pointing anything at a production system.

| Lab | What it is | Run it |
| --- | --- | --- |
| [`vulnerable-api`](vulnerable-api/) | A dependency-free API with nine planted bugs across the classes that pay in web/API bounties (BOLA, BFLA, mass assignment, JWT `alg:none`, data exposure, SQLi, OTP brute force, business logic) | `python labs/vulnerable-api/server.py --port 8080` |

## Rules

- **Local only.** Never deploy a lab to a network you do not control.
- **All data is fake.** Seeded credentials exist to be abused; they are not
  secrets and must not be rotated into anything real.
- **Reproduce by hand first.** The reference scripts show what a finished
  finding looks like, not how to find one.
- **Keep them honest.** Each lab has tests asserting its weaknesses are still
  exploitable, so a well-meant "fix" fails CI instead of silently removing the
  practice material.

See the [practice lab guide](../docs/usage/practice-lab.mdx) for the workflow.
