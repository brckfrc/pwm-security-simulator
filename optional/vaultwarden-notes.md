# Vaultwarden Reference Demo (Optional)

This optional section describes how a local Vaultwarden instance can be used
as a real-world reference alongside the simulator.  It is **not implemented**
as part of the main deliverable.

---

## What is Vaultwarden?

[Vaultwarden](https://github.com/dani-garcia/vaultwarden) is an unofficial,
open-source Bitwarden-compatible server implementation written in Rust.  It
can be self-hosted locally using Docker, making it a convenient reference for
how a real password manager stores and handles vault data.

---

## Purpose of the Optional Demo

- Show a realistic password manager environment running locally.
- Create dummy credentials through the Bitwarden web client connected to the
  local Vaultwarden server.
- Illustrate that real password managers use the same vault model: client-side
  encryption, KDF-derived keys, and authenticated vault blobs stored on the
  server.
- Connect the simulator's educational concepts to a concrete open-source
  implementation.

---

## How to Run (if implemented)

### Prerequisites

- Docker and Docker Compose installed.

### Steps

```bash
# Pull and run Vaultwarden
docker run -d \
  --name vaultwarden \
  -p 8080:80 \
  -e SIGNUPS_ALLOWED=true \
  vaultwarden/server:latest
```

Open `http://localhost:8080` in a browser, create an account with a test
master password, and add a few dummy vault items.

To inspect the encrypted vault blob Vaultwarden stores, query the SQLite
database:

```bash
docker exec -it vaultwarden sqlite3 /data/db.sqlite3 \
  "SELECT data FROM ciphers LIMIT 1;"
```

The blob is base64-encoded, AES-256-CBC encrypted, and HMAC-SHA256 authenticated
on the client side — mirroring the secure vault design in this simulator.

---

## Notes on Bitwarden's KDF Transition

Bitwarden migrated from PBKDF2-SHA256 (600,000 iterations by default) to
Argon2id (t=3, m=64 MiB, p=4) in late 2023.  This transition is one of the
real-world motivations for including Argon2id in the simulator's KDF benchmark.

Reference: https://bitwarden.com/help/kdf-algorithms/
