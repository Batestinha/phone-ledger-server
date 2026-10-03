# Phone Ledger sync protocol v1

All public API paths are rooted at `/v1`. JSON uses UTF-8, rejects unknown fields, and is limited to 64 KiB. Vault bodies use `application/octet-stream` and are limited to 64 MiB. Binary values in JSON and headers use unpadded base64url. Account and device IDs are 16 random bytes encoded as 32 lowercase hexadecimal characters.

## Discovery and enrollment

`GET /v1/status` returns `protocolVersion`, a stable UUID `instanceId`, `maxVaultBytes`, and registration mode.

`POST /v1/accounts` consumes a one-use invite and atomically creates an account, its first Ed25519 device, and a token family. The client sends an account ID, device ID/name/public key, and `SHA-256(enrollmentSecret)`.

`POST /v1/devices/enroll` accepts an account ID, a 32-byte enrollment secret, and a new device. The server hashes the supplied secret and compares it in constant time with the stored verifier.

The client holds a random 32-byte recovery root and derives two independent keys:

1. `salt = SHA-256(instanceId || 0x00 || accountId)`
2. `prk = HMAC-SHA256(salt, recoveryRoot)`
3. `payloadKey = HMAC-SHA256(prk, "phone-ledger/v1/payload" || 0x01)`
4. `enrollmentSecret = HMAC-SHA256(prk, "phone-ledger/v1/enrollment" || 0x01)`

The recovery phrase is the standard 24-word English BIP-39 encoding of the 256-bit recovery root (256 entropy bits plus an eight-bit checksum). It is a transport/backup representation, not a password KDF.

## Device authentication and tokens

`POST /v1/auth/challenges` takes account and device IDs and returns a random, one-minute, one-use challenge ID and 32-byte nonce.

The device signs a canonical message made by prefixing each of these six byte strings with a four-byte unsigned big-endian length:

1. `phone-ledger-auth-v1`
2. server instance ID (UTF-8)
3. account ID (UTF-8)
4. device ID (UTF-8)
5. challenge ID (UTF-8)
6. nonce

`POST /v1/auth/tokens` exchanges the challenge ID and Ed25519 signature for opaque access and refresh tokens. `POST /v1/auth/refresh` rotates a refresh token. Reusing a rotated token revokes its whole family. The server stores SHA-256 token hashes, never bearer tokens.

Cross-language canonical-message test vector:

```text
instanceId = inst
accountId  = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
deviceId   = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
challenge  = challenge
nonce      = 00010203
base64url  = AAAAFHBob25lLWxlZGdlci1hdXRoLXYxAAAABGluc3QAAAAgYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEAAAAgYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIAAAAJY2hhbGxlbmdlAAAABAABAgM
```

## Vaults and conflicts

Authenticated `GET /v1/vault` returns the latest opaque blob with:

- `ETag: "<revision>"`
- `X-Phone-Ledger-Format: 1`
- `X-Content-SHA256: <base64url SHA-256 of body>`

An empty vault returns `204` and revision zero. The client checks the digest before attempting decryption.

Authenticated `PUT /v1/vault` sends the same format/digest headers and `If-Match: "<base revision>"`. A base below the current server revision returns `409` with the current ETag. A base above the current server revision is accepted as rollback recovery, preserving monotonic client-observed revision numbers and returning `X-Phone-Ledger-Rollback-Recovery: true`.

The encrypted envelope is:

```text
"PLS" || 0x02 || 12-byte random nonce || AES-256-GCM ciphertext and 16-byte tag
```

AES-GCM additional authenticated data is UTF-8 `phone-ledger-vault-v1 || 0x00 || instanceId || 0x00 || accountId`.

Client plaintext is schema-versioned JSON. Version 3 assigns every phone, target, and disclosure event a Lamport-style `(counter, writerId)` mutation stamp. Devices merge by ID and choose the lexicographically greatest stamp; tombstones are retained. This avoids using wall clocks for conflict correctness.

## Recovery rotation and device revocation

Authenticated `PUT /v1/recovery` has vault upload headers plus `X-Phone-Ledger-Enrollment-Verifier`. In one transaction the server writes the newly encrypted vault, replaces the verifier, revokes every other device/token family, and removes older online vault revisions.

The Android client persists the pending new recovery root before sending this non-idempotent request. If a network response is lost, it downloads the current vault and tests authenticated decryption with the pending and prior roots, allowing the same rotation to finish without losing the new key.

`GET /v1/devices` lists enrolled devices. `DELETE /v1/devices/{deviceID}` revokes the device and all of its token families. A device may revoke itself when disconnecting.
