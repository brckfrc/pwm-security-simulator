# Password Manager KDF and Vault Integrity Security Simulation

## Project Title

**Security Simulation of KDF and Vault Integrity Weaknesses in Password Managers**

## Course Project Context

This project demonstrates two important security concepts in password managers:

1. **Key Derivation Function (KDF) security**
2. **Vault integrity protection**

Modern password managers do not usually store user passwords in plaintext. Instead, they derive an encryption key from the user's master password and use that key to encrypt the vault. However, encryption alone is not enough. A secure password manager must also protect the integrity of the vault and prevent attackers from modifying encrypted data or weakening cryptographic parameters.

This project implements a small local password manager security simulator to demonstrate these concepts in a safe and controlled environment.

---

## Main Goal

The main goal is to build a working security simulator that shows:

* How a master password is transformed into an encryption key using a KDF.
* How KDF iteration count affects brute-force resistance.
* Why vault encryption alone is not sufficient.
* How vault tampering can be detected using authenticated encryption or integrity checks.
* The difference between an insecure vault design and a secure vault design.

---

## Scope

The project will be implemented as a local web application using **Python** and **Streamlit**.

The application will not attack any real password manager or real user data. All demonstrations will be performed on locally generated dummy vault data.

---

## Technologies

* Python
* Streamlit
* `cryptography` library (PBKDF2, AES-GCM, AES-CTR)
* `argon2-cffi` library (Argon2id)
* JSON-based local vault file
* PBKDF2 and Argon2id for key derivation
* AES-GCM (AEAD) for authenticated encryption in secure mode
* AES-CTR without integrity protection for insecure mode
* Optional: Docker-based local Vaultwarden instance as a real-world reference

All `requirements.txt` dependencies will be pinned to specific versions.

---

## Localization

* All source code, variable names, and the Streamlit user interface are in **English**.
* Only the final one-page report is written in **Turkish**.

---

## Core Features

### 1. Master Password and KDF Demo

The user enters a master password. The application derives an encryption key from it using PBKDF2 and Argon2id, then compares them.

The simulator compares different PBKDF2 iteration counts, such as:

* 1,000 iterations
* 100,000 iterations
* 600,000 iterations

It also derives a key using **Argon2id** (a modern, memory-hard KDF) with a configurable time/memory cost, so the user can compare an iteration-based KDF against a memory-hard KDF.

The application displays how long each key derivation takes.

**Purpose:**
To show that a higher KDF iteration count increases the computational cost of brute-force attacks, and that memory-hard KDFs like Argon2id resist GPU/ASIC-based attacks better than PBKDF2. This mirrors the real-world shift of password managers such as Bitwarden/Vaultwarden from PBKDF2 to Argon2id.

---

### 2. Insecure Vault Mode

The simulator creates a dummy password vault record such as:

* Website
* Username
* Password
* Notes

In insecure mode, the vault data is encrypted using **AES-CTR with no integrity protection (no MAC)**. The KDF parameters (salt, iteration count) are stored in plaintext and are **not** cryptographically bound to the ciphertext.

The application includes a tampering simulation where the local vault file is modified. Because AES-CTR is malleable, the simulator can demonstrate a **bit-flipping attack**: without knowing the key, an attacker flips specific ciphertext bytes to produce predictable changes in the decrypted plaintext.

**Expected result:**
The vault decrypts "successfully" even after tampering, returning attacker-controlled data. The system cannot detect that the vault was modified.

**Security lesson:**
Encryption alone does not guarantee data integrity. A malleable cipher without a MAC lets an attacker modify plaintext without the key.

---

### 3. Secure Vault Mode

The same dummy vault data is protected using **AES-GCM (authenticated encryption / AEAD)**.

The KDF parameters (salt, iteration count, KDF type) and a monotonic vault **version number** are passed as AES-GCM **associated data (AAD)**, so they are authenticated even though they are not encrypted. This binds the cryptographic parameters and version to the ciphertext.

If the vault file is modified in any way (ciphertext, tag, KDF parameters, or version), the application detects the tampering and refuses to decrypt the data.

**Expected result:**
The application displays an error such as:

```text
Vault integrity check failed.
```

**Security lesson:**
Authenticated encryption protects both confidentiality and integrity.

---

### 4. Vault Tampering Simulation

The application includes controlled tamper buttons that modify the local vault file. Each tampering scenario is run against both the insecure vault and the secure vault to contrast the outcomes.

Tampering scenarios:

* **Ciphertext modification / bit-flipping** - flip ciphertext bytes (insecure mode shows predictable, targeted plaintext changes; secure mode fails the integrity check).
* **KDF parameter downgrade** - lower the stored KDF cost parameter (insecure mode accepts the change with no integrity signal — though, because the parameter no longer matches encryption time, the wrong key is derived and the data is garbled; secure mode detects it because the parameters are bound via AAD). The real-world downgrade threat is at enrollment/re-encryption time, before the key is derived.
* **Version-field tampering (in place)** - edit the stored `version` field without touching the ciphertext (insecure mode accepts it silently; secure mode detects it because the version is bound via AAD).
* **Full-file replay / rollback** - replace the entire vault with an intact older snapshot (succeeds in *both* modes, since the old file was validly encrypted; AAD cannot detect this — real replay protection needs an external monotonic counter).
* **Metadata modification** - change unencrypted metadata fields not covered by AAD.

The goal is not to perform a real-world exploit, but to demonstrate how weak integrity protection can create security risks.

---

## Optional Feature: Vaultwarden Reference Demo

If time allows, a local Vaultwarden instance may be deployed using Docker.

Vaultwarden will be used only as a real-world reference environment to show how password manager systems store encrypted vault data and rely on client-side encryption principles.

This optional part will not be the main project deliverable.

**Purpose of optional Vaultwarden demo:**

* Show a real password manager-like environment.
* Create dummy credentials.
* Demonstrate that password managers use a vault-based model.
* Connect the simulator concepts to a real open-source password manager ecosystem.

---

## Demo Flow

The final demonstration will follow this order:

1. Open the Streamlit application.
2. Enter a sample master password.
3. Run the KDF benchmark and compare PBKDF2 iteration counts and Argon2id timings.
4. Create a dummy vault item.
5. Save the vault in insecure mode (AES-CTR, no integrity).
6. Tamper with the insecure vault (bit-flipping, KDF downgrade, replay) and show the changes go undetected.
7. Save the vault in secure mode (AES-GCM with AAD-bound parameters and version).
8. Run the same tampering scenarios on the secure vault: in-place edits (bit-flip, KDF downgrade, version-field change) fail integrity verification, while full-file replay still succeeds — motivating the need for an external monotonic counter.
9. Optionally show the local Vaultwarden environment if implemented.

---

## Expected Deliverables

### 1. Working Application

A local Streamlit application that can be run with:

```bash
streamlit run app.py
```

### 2. Source Code

The source code will include:

```text
app.py
requirements.txt
README.md
PLAN.md
vault_samples/
```

### 3. One-Page Report (Turkish)

The report (written in Turkish) will summarize:

* Project goal
* KDF explanation
* Vault integrity explanation
* Used technologies
* Demo scenarios
* Security conclusion

---

## Project Structure

```text
password-manager-security-simulator/
│
├── app.py                  # Streamlit UI (English)
├── kdf.py                  # PBKDF2 + Argon2id derivation and benchmarking
├── vault.py                # insecure (AES-CTR) and secure (AES-GCM) vault logic
├── requirements.txt        # pinned versions
├── README.md
├── PLAN.md
├── rapor.md                # one-page report (Turkish)
│
├── vault_samples/
│   ├── insecure_vault.json
│   └── secure_vault.json
│
└── optional/
    └── vaultwarden-notes.md
```

---

## Security and Ethics

This project is designed for educational purposes only.

It does not target real password manager users, real credentials, real servers, or production systems. All demonstrations are performed on locally generated dummy data.

The purpose is to understand password manager security principles, especially KDF configuration and vault integrity protection.

---

## Success Criteria

The project will be considered successful if it can clearly demonstrate:

* A master password being converted into an encryption key using both PBKDF2 and Argon2id.
* The performance difference between low and high KDF iteration counts, and between PBKDF2 and a memory-hard KDF.
* A vault tampering scenario in an insecure design (including a bit-flipping attack and a KDF parameter downgrade that go undetected).
* The same tampering scenarios being detected and rejected in a secure (AES-GCM) design.
* A clear explanation of why password managers need both confidentiality and integrity, including protection of cryptographic parameters and vault version.

---

## Final Message of the Project

A password manager should not only encrypt vault data. It must also protect the integrity of vault contents and cryptographic parameters. Otherwise, an attacker may not need to directly read the vault to weaken or manipulate the system.
