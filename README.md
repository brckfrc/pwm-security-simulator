# Password Manager KDF and Vault Integrity Security Simulator

An educational local web application that demonstrates two core security
properties of password managers:

1. **KDF strength** – how key derivation function choice and iteration count
   affect brute-force resistance (PBKDF2 vs Argon2id).
2. **Vault integrity** – why encryption alone is insufficient and how
   authenticated encryption (AES-GCM) detects tampering that goes unnoticed
   in an encryption-only design (AES-CTR).

All demonstrations use locally generated dummy data. No real credentials or
servers are involved.

---

## Requirements

- Python 3.10+
- A virtual environment (recommended)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
streamlit run app.py
```

The app opens in your browser at `http://localhost:8501`.

---

## Project Structure

```
├── app.py                  Streamlit UI
├── kdf.py                  PBKDF2 and Argon2id derivation + benchmark
├── vault.py                Insecure (AES-CTR) and secure (AES-GCM) vault logic
├── requirements.txt        Pinned dependencies
├── README.md               This file
├── docs/
│   ├── PLAN.md             Project design document
│   └── rapor.md            One-page Turkish report
├── tests/                  pytest suite (round-trips + tamper detection)
├── vault_samples/          Vault files generated at runtime
│   ├── insecure_vault.json
│   └── secure_vault.json
└── optional/
    └── vaultwarden-notes.md  Reference notes on Vaultwarden (optional demo)
```

---

## Demo Flow

1. Open the app (`streamlit run app.py`).
2. Enter a master password and run the KDF benchmark to compare timings.
3. Fill in a dummy vault item and save it in both insecure and secure modes.
4. Run the tampering scenarios (bit-flip, KDF downgrade, replay, metadata) and
   observe which mode detects the attack.

---

## Security Note

This project is for educational purposes only. It does not target real
password managers, real user data, or any production system.
