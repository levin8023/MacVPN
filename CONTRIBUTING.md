# Contributing

Use generic names, RFC 5737 example endpoints, and synthetic credentials in code, screenshots, issues, and tests.
Never commit local JSON, private networks, real accounts, passwords, logs, build products, or developer home paths.

Run `./scripts/test.sh` and `./build-app.sh` before proposing a change. Tests must run offline without sudo or real VPN access.
For network fixes, describe the scenario and whether it was verified on a real gateway; redact sensitive details.

Keep each pull request focused and explain the behavior change, validation, and remaining limitations.
Build products belong in GitHub Releases, not in Git history.
