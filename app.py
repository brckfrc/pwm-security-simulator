"""
Password Manager KDF and Vault Integrity Security Simulator
Streamlit UI - educational demo only, all data is locally generated dummy data.
"""

import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st

import kdf as kdf_module
import vault as vault_module

VAULT_DIR = Path("vault_samples")
INSECURE_PATH = VAULT_DIR / "insecure_vault.json"
SECURE_PATH = VAULT_DIR / "secure_vault.json"

VAULT_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="PWM Security Simulator",
    page_icon="🔐",
    layout="wide",
)

st.title("Password Manager Security Simulator")
st.caption(
    "Educational demo · KDF strength · Vault integrity · Tampering scenarios "
    "| All data is locally generated dummy data"
)

# ---------------------------------------------------------------------------
# Session state initialisation
# ---------------------------------------------------------------------------

for key, default in {
    "kdf_results": None,
    "insecure_snapshot": None,  # JSON string taken before tampering (for replay)
    "secure_snapshot": None,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


# ---------------------------------------------------------------------------
# Helper: render a result dict from decrypt
# ---------------------------------------------------------------------------

def render_decrypt_result(result: dict, mode_label: str):
    if result.get("_corrupted"):
        st.error(
            f"**{mode_label}** — Decryption returned corrupted data (no integrity "
            f"check raised an error).\n\nRaw hex (first 64 chars): `{result['_raw'][:64]}…`"
        )
        st.warning(
            "The system accepted the tampered ciphertext without complaint. "
            "This is the danger of encryption-only (no MAC)."
        )
    else:
        st.success(f"**{mode_label}** — Decrypted successfully:")
        st.json(result)


def render_integrity_error(err: vault_module.IntegrityError, mode_label: str):
    st.error(f"**{mode_label}** — `{err}`")
    st.info("AES-GCM detected the modification and refused to decrypt the vault.")


# ---------------------------------------------------------------------------
# Section 1: KDF Benchmark
# ---------------------------------------------------------------------------

st.header("1 · KDF Benchmark")
st.markdown(
    "Enter a master password and run the benchmark to see how long each "
    "key derivation function takes. A higher cost means brute-force attacks "
    "require proportionally more work from an attacker."
)

with st.form("kdf_form"):
    master_password = st.text_input(
        "Master password",
        value="correct-horse-battery-staple",
        type="password",
    )
    run_benchmark = st.form_submit_button("Run KDF Benchmark")

if run_benchmark:
    if not master_password:
        st.warning("Please enter a master password.")
    else:
        with st.spinner("Running key derivation benchmark…"):
            results = kdf_module.benchmark(master_password)
            st.session_state.kdf_results = results

if st.session_state.kdf_results:
    results = st.session_state.kdf_results
    df = pd.DataFrame(
        [
            {
                "KDF Configuration": r.label,
                "Parameters": r.iterations_or_params,
                "Time (ms)": r.elapsed_ms,
                "Key preview": r.key_hex,
            }
            for r in results
        ]
    )

    col_table, col_chart = st.columns([2, 3])
    with col_table:
        st.dataframe(df[["KDF Configuration", "Parameters", "Time (ms)"]], hide_index=True)
    with col_chart:
        chart_df = df.set_index("KDF Configuration")[["Time (ms)"]]
        st.bar_chart(chart_df)

    st.info(
        "**Key insight:** PBKDF2 with 600,000 iterations takes ~100× longer than "
        "1,000 iterations, directly multiplying the cost of every brute-force guess. "
        "Argon2id is also memory-hard, which defeats GPU/ASIC attacks that PBKDF2 "
        "cannot resist (parallel cracking is cheap on GPUs when memory is not a constraint)."
    )

st.divider()

# ---------------------------------------------------------------------------
# Section 2: Create a Dummy Vault Item
# ---------------------------------------------------------------------------

st.header("2 · Create a Dummy Vault Item")

with st.form("vault_item_form"):
    col1, col2 = st.columns(2)
    with col1:
        website = st.text_input("Website", value="example.com")
        username = st.text_input("Username", value="alice@example.com")
    with col2:
        item_password = st.text_input("Password", value="SuperSecret!42", type="password")
        notes = st.text_area("Notes", value="Main account", height=68)

    vault_password = st.text_input(
        "Vault master password (used to encrypt)",
        value="correct-horse-battery-staple",
        type="password",
        key="vault_pw",
    )

    col_save1, col_save2 = st.columns(2)
    with col_save1:
        save_insecure = st.form_submit_button("💾 Save — Insecure (AES-CTR, no MAC)")
    with col_save2:
        save_secure = st.form_submit_button("🔒 Save — Secure (AES-GCM + AAD)")

item_data = {
    "website": website,
    "username": username,
    "password": item_password,
    "notes": notes,
}

if save_insecure:
    if not vault_password:
        st.warning("Please enter a vault master password.")
    else:
        vault_module.encrypt_insecure(item_data, vault_password, INSECURE_PATH)
        # Take a snapshot for the replay tamper demo
        st.session_state.insecure_snapshot = vault_module.save_vault_snapshot(INSECURE_PATH)
        st.success(f"Insecure vault saved to `{INSECURE_PATH}`")

if save_secure:
    if not vault_password:
        st.warning("Please enter a vault master password.")
    else:
        vault_module.encrypt_secure(item_data, vault_password, SECURE_PATH, version=1)
        st.session_state.secure_snapshot = vault_module.save_vault_snapshot(SECURE_PATH)
        st.success(f"Secure vault saved to `{SECURE_PATH}`")

# Show vault files on disk
if INSECURE_PATH.exists() or SECURE_PATH.exists():
    with st.expander("View vault files on disk"):
        if INSECURE_PATH.exists():
            st.subheader("insecure_vault.json")
            st.code(INSECURE_PATH.read_text(), language="json")
        if SECURE_PATH.exists():
            st.subheader("secure_vault.json")
            st.code(SECURE_PATH.read_text(), language="json")

st.divider()

# ---------------------------------------------------------------------------
# Section 3: Vault Tampering Scenarios
# ---------------------------------------------------------------------------

st.header("3 · Vault Tampering Scenarios")
st.markdown(
    "Each button modifies the vault file on disk, then attempts to decrypt it. "
    "Compare what the insecure vault (AES-CTR) and the secure vault (AES-GCM) do "
    "when they encounter the tampered data."
)

decrypt_password = st.text_input(
    "Vault master password (for decryption after tampering)",
    value="correct-horse-battery-staple",
    type="password",
    key="decrypt_pw",
)


def require_vault(path: Path, label: str) -> bool:
    if not path.exists():
        st.warning(f"No {label} vault found. Save one in Section 2 first.")
        return False
    return True


# --- Scenario A: Bit-flip ---
with st.expander("Scenario A · Bit-flip attack (AES-CTR malleability)", expanded=True):
    st.markdown(
        "**What happens:** One byte in the ciphertext is flipped. "
        "In AES-CTR, flipping a ciphertext bit flips the same bit in the plaintext "
        "(no MAC → no detection). "
        "In AES-GCM, the authentication tag is invalid → `IntegrityError`."
    )
    col_a1, col_a2 = st.columns(2)

    with col_a1:
        if st.button("Flip a ciphertext byte — Insecure vault", key="flip_insecure"):
            if require_vault(INSECURE_PATH, "insecure"):
                msg = vault_module.tamper_bitflip(INSECURE_PATH)
                st.warning(f"Tampered: {msg}")
                try:
                    result = vault_module.decrypt_insecure(decrypt_password, INSECURE_PATH)
                    render_decrypt_result(result, "Insecure vault")
                except Exception as e:
                    st.error(f"Unexpected error: {e}")

    with col_a2:
        if st.button("Flip a ciphertext byte — Secure vault", key="flip_secure"):
            if require_vault(SECURE_PATH, "secure"):
                msg = vault_module.tamper_bitflip(SECURE_PATH)
                st.warning(f"Tampered: {msg}")
                try:
                    vault_module.decrypt_secure(decrypt_password, SECURE_PATH)
                    st.error("Expected IntegrityError was NOT raised — something is wrong.")
                except vault_module.IntegrityError as e:
                    render_integrity_error(e, "Secure vault")

# --- Scenario B: KDF parameter downgrade ---
with st.expander("Scenario B · KDF parameter downgrade"):
    st.markdown(
        "**What happens:** The stored iteration count is lowered from 600,000 to 1,000. "
        "In the insecure vault the wrong key is derived (data is garbled), and the system "
        "gives no security warning. "
        "In the secure vault the KDF params are part of the AAD → "
        "any change is caught immediately."
    )
    col_b1, col_b2 = st.columns(2)

    with col_b1:
        if st.button("Downgrade KDF iterations — Insecure vault", key="kdf_insecure"):
            if require_vault(INSECURE_PATH, "insecure"):
                msg = vault_module.tamper_downgrade_kdf(INSECURE_PATH)
                st.warning(f"Tampered: {msg}")
                try:
                    result = vault_module.decrypt_insecure(decrypt_password, INSECURE_PATH)
                    render_decrypt_result(result, "Insecure vault")
                except Exception as e:
                    st.error(f"Unexpected error (no IntegrityError, just garbled data): {e}")

    with col_b2:
        if st.button("Downgrade KDF iterations — Secure vault", key="kdf_secure"):
            if require_vault(SECURE_PATH, "secure"):
                msg = vault_module.tamper_downgrade_kdf(SECURE_PATH)
                st.warning(f"Tampered: {msg}")
                try:
                    vault_module.decrypt_secure(decrypt_password, SECURE_PATH)
                    st.error("Expected IntegrityError was NOT raised — something is wrong.")
                except vault_module.IntegrityError as e:
                    render_integrity_error(e, "Secure vault")

# --- Scenario C: Version-field tampering / rollback ---
with st.expander("Scenario C · Version-field rollback (what AAD actually protects)"):
    st.markdown(
        "**What happens:** The `version` field in the vault JSON is lowered "
        "(e.g. 1 → 0) without touching the ciphertext. "
        "In the insecure vault this metadata change is silent and the vault "
        "decrypts as normal with the attacker-chosen version. "
        "In the secure vault the version is part of the AAD, so changing it "
        "invalidates the GCM authentication tag and decryption fails."
    )
    st.info(
        "**Note on full-vault replay:** Replacing the entire vault file with "
        "an intact older snapshot succeeds at the crypto layer in *both* modes "
        "because the old vault was validly encrypted. True replay protection "
        "requires an external monotonic counter (e.g. a server-side version "
        "registry) outside the vault file itself. Version-in-AAD protects only "
        "against *in-place* version-field modification."
    )

    col_c1, col_c2 = st.columns(2)

    with col_c1:
        if st.button("Downgrade version field — Insecure vault", key="version_insecure"):
            if require_vault(INSECURE_PATH, "insecure"):
                msg = vault_module.tamper_version_field(INSECURE_PATH, new_version=0)
                st.warning(f"Tampered: {msg}")
                try:
                    result = vault_module.decrypt_insecure(decrypt_password, INSECURE_PATH)
                    render_decrypt_result(result, "Insecure vault")
                    st.warning("Version field was altered silently — no error raised.")
                except Exception as e:
                    st.error(f"Unexpected error: {e}")

    with col_c2:
        if st.button("Downgrade version field — Secure vault", key="version_secure"):
            if require_vault(SECURE_PATH, "secure"):
                msg = vault_module.tamper_version_field(SECURE_PATH, new_version=0)
                st.warning(f"Tampered: {msg}")
                try:
                    vault_module.decrypt_secure(decrypt_password, SECURE_PATH)
                    st.error("Expected IntegrityError was NOT raised — something is wrong.")
                except vault_module.IntegrityError as e:
                    render_integrity_error(e, "Secure vault")

# --- Scenario D: Metadata modification ---
with st.expander("Scenario D · Unprotected metadata modification"):
    st.markdown(
        "**What happens:** The `mode` label in the vault JSON is changed. "
        "This field is **not** included in AAD, so both modes accept the change — "
        "demonstrating that only explicitly authenticated fields are protected. "
        "This shows the importance of carefully choosing what goes into AAD."
    )
    col_d1, col_d2 = st.columns(2)

    with col_d1:
        if st.button("Modify metadata — Insecure vault", key="meta_insecure"):
            if require_vault(INSECURE_PATH, "insecure"):
                msg = vault_module.tamper_metadata(INSECURE_PATH)
                st.warning(f"Tampered: {msg}")
                try:
                    result = vault_module.decrypt_insecure(decrypt_password, INSECURE_PATH)
                    render_decrypt_result(result, "Insecure vault")
                except Exception as e:
                    st.error(f"Error: {e}")

    with col_d2:
        if st.button("Modify metadata — Secure vault", key="meta_secure"):
            if require_vault(SECURE_PATH, "secure"):
                msg = vault_module.tamper_metadata(SECURE_PATH)
                st.warning(f"Tampered: {msg}")
                try:
                    result = vault_module.decrypt_secure(decrypt_password, SECURE_PATH)
                    render_decrypt_result(result, "Secure vault")
                    st.warning(
                        "The mode label is NOT in AAD, so this modification goes undetected. "
                        "Only fields in AAD are protected by AES-GCM."
                    )
                except vault_module.IntegrityError as e:
                    render_integrity_error(e, "Secure vault")

st.divider()

# ---------------------------------------------------------------------------
# Section 4: Key Takeaways
# ---------------------------------------------------------------------------

st.header("4 · Key Takeaways")

st.markdown("""
| Property | Insecure vault (AES-CTR) | Secure vault (AES-GCM) |
|---|---|---|
| Encryption | ✅ AES-CTR | ✅ AES-GCM |
| Integrity / MAC | ❌ None | ✅ GCM authentication tag |
| KDF params protected | ❌ Plaintext, unauthenticated | ✅ Bound via AAD |
| Vault version protected | ❌ Unauthenticated | ✅ Bound via AAD |
| Bit-flip attack | ❌ Undetected (garbled data) | ✅ Detected |
| KDF downgrade | ❌ Undetected | ✅ Detected |
| Replay / rollback | ❌ Undetected | ✅ Detected |
| Unprotected metadata | ❌ Undetected | ⚠️ Only if field is in AAD |

**Conclusion:** A password manager must protect *both* the confidentiality of vault
data *and* the integrity of ciphertext and cryptographic parameters.
Encryption alone is not enough.
""")
