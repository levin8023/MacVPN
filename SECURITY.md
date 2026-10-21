# Security

Do not post credentials, local configuration, or unredacted logs in public issues.
For a suspected vulnerability, use the repository's private vulnerability reporting feature if available.
If it is unavailable, open an issue requesting a private reporting channel without disclosing the vulnerability details.

The client manages privileged network processes and supports legacy IKEv1 gateways.
Only use configurations and binaries you trust. Do not disable macOS security protections to run an unknown build.
Credentials are stored in an app-managed JSON file under Application Support, with mode 600. It is plaintext local storage, not a keychain or an encrypted vault.

No supported-release security response SLA is currently provided. This is preview software.
