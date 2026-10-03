# Phone Ledger Server

The standalone, self-hosted sync service for [Phone Ledger for Android](https://github.com/Batestinha/phone-ledger-android). The Android client and server deliberately live in separate repositories: mobile releases do not require a server deployment, and server operators can upgrade or audit this small service independently.

Phone Ledger remains local-first. This server stores encrypted vault blobs, opaque token hashes, device public keys, and a verifier derived from the recovery key. It never receives phone numbers, disclosure records, the recovery root, or a payload-decryption key in plaintext.

## Status

Version 0.3 is the first standalone-sync release candidate. It has automated authentication, conflict, rollback, rotation, revocation, backup, and protocol-vector tests. It has not received an independent security audit. Keep backups and test recovery before relying on it as the only copy of important data.

## Quick start with Docker Compose

The service speaks HTTP on loopback by default. Put a trusted HTTPS reverse proxy in front of it; the Android client intentionally refuses HTTP and redirects.

```sh
docker compose build
docker compose up -d
docker compose exec phone-ledger-server phone-ledger-server invite --db /data/phone-ledger.db --ttl 10m
```

In the Android app, open **Settings & data → Configure self-hosted sync → Create account**, enter the public HTTPS server root and the one-use invite. Save the generated 24-word recovery kit offline. The invite is stored only as a SHA-256 hash and is consumed transactionally.

The sample Compose deployment binds only `127.0.0.1:8080`, drops Linux capabilities, uses a read-only root filesystem, runs as UID/GID 10001, and caps the service at one CPU and 512 MiB. Configure your reverse proxy with a request-body limit of at least 65 MiB and timeouts above 90 seconds. Do not expose port 8080 directly to the internet.

## Native build

Go 1.26 or newer is required.

```sh
go test -race -p=2 ./...
CGO_ENABLED=0 go build -trimpath -o phone-ledger-server ./cmd/phone-ledger-server
./phone-ledger-server serve --listen 127.0.0.1:8080 --db ./data/phone-ledger.db
```

Commands:

- `serve`: run the HTTP service. TLS termination belongs in a reverse proxy.
- `invite`: print a random, expiring invite. The default is one use and 10 minutes.
- `backup`: create a consistent SQLite backup with `VACUUM INTO`. It refuses to overwrite an existing destination.
- `version`: print the embedded build version.

Example backup:

```sh
docker compose exec phone-ledger-server phone-ledger-server backup \
  --db /data/phone-ledger.db --output /data/phone-ledger-2026-10-03.db.backup
```

Copy the resulting file off the Docker volume, protect it as sensitive data, and periodically prove that it opens on a separate test deployment. Preserve the database as a unit: its stable instance ID is part of client key derivation. Restoring an older database is supported; an enrolled client detects the lower server revision and repairs it from its local encrypted vault.

## Security model

- Each client creates a random 256-bit recovery root and derives separate payload-encryption and enrollment secrets with HKDF-SHA256.
- Vault data is encrypted and authenticated client-side with AES-256-GCM. Context binding includes the server instance ID and account ID.
- Devices use independent Ed25519 key pairs. A short-lived, one-use server challenge proves possession before the server issues tokens.
- Access tokens live for 15 minutes. Refresh tokens live for 30 days, rotate on every use, and revoke the token family if reuse is detected.
- Recovery-key rotation atomically installs a new verifier and encrypted vault, revokes other devices, and removes older online vault revisions. Old offline database backups still require separate retention and destruction policy.
- SQLite uses WAL mode, foreign keys, a five-second busy timeout, and one connection to serialize writes. Database, WAL, shared-memory, and backup files are chmod `0600` when managed by the service.
- API responses are `no-store`; logs contain request method, path, status, and duration, but not request bodies, tokens, account IDs, or device IDs.

See [SECURITY.md](SECURITY.md) for boundaries and [PROTOCOL.md](PROTOCOL.md) for the interoperable wire format.

## Upgrading from the AliasVault-based alpha

The Android v0.3 client recognizes the old local AliasVault sync configuration. It can perform one authenticated final fetch, merge that ledger locally, then create or join a standalone Phone Ledger account. After the new encrypted upload is read back and verified, the client removes the old credentials from its local vault. The migration does not delete the AliasVault remote blob; remove it under your own retention policy after verifying all devices.

## License

GNU Affero General Public License v3.0. This is an independent Phone Ledger project, not an official AliasVault product.
