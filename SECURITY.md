# Security policy

## Reporting a vulnerability

Do not put exploit details, tokens, recovery material, or user data in a public issue. Use GitHub's private vulnerability-reporting facility for this repository when available. If it is unavailable, contact the repository owner privately through the contact method on their GitHub profile and include only enough information to establish a secure follow-up channel.

## Supported versions

Only the newest tagged release is intended to receive security fixes. Until a stable tag is published, treat every build as a release candidate.

## Trust boundaries

The Android client is responsible for encryption, decryption, recovery-key custody, merge semantics, and validating downloaded plaintext after authenticated decryption. The server is trusted for availability, revision ordering, device authorization, and ciphertext retention—not for confidentiality of ledger contents.

TLS is mandatory between Android and the public endpoint. This binary intentionally provides plain HTTP for use behind a reverse proxy. Operators are responsible for certificate renewal, proxy hardening, host patching, private backups, database-volume access, monitoring, and denial-of-service controls beyond the built-in bounded bodies and per-IP request limits.

Compromise of the live server reveals ciphertext sizes, timing, IP metadata, device names/public keys, opaque account/device IDs, and token/enrollment hashes. It should not reveal phone numbers or disclosure records without a recovery root or a compromised unlocked client. A malicious server can deny service, replay or roll back ciphertext, or omit writes; clients authenticate ciphertext and use monotonically tracked revisions to detect and repair ordinary rollback, but no centralized service can guarantee availability against its own operator.

Recovery words and recovery QR codes are bearer secrets. Anyone who obtains them and the account ID can enroll a new device and decrypt the latest vault. Recovery rotation revokes other live devices, but cannot erase copies in old offline server backups or already-compromised clients.

## Operational checklist

- Terminate TLS with a current reverse proxy and expose only HTTPS publicly.
- Restrict port 8080 to loopback or a private container network.
- Protect the data volume and backups; do not synchronize them through consumer cloud folders.
- Generate one-use, short-lived invites and transmit them out of band.
- Monitor authentication and rate-limit events without logging request bodies or authorization headers.
- Test backup restoration and Android recovery enrollment before an incident.
- Update to the newest client and server together when the protocol version changes.
