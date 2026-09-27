"""
crypto_vault.py — passphrase-protected secret storage + AES-256-GCM image vault.

Design note (why this isn't just module-level globals like the notebook):
Importing this module must NOT prompt for a passphrase — that surprised
behaviour only worked in a notebook where "importing" and "running" are the
same action. Here, call `load_secrets()` explicitly, once, from main.py.
Every other function that needs a secret calls the small getters below,
which raise a clear error if you forgot to unlock the vault first.
"""
import base64
import hashlib
import os
import secrets
import stat
import struct
import getpass

import cv2
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as crypto_hashes

import config


class SecretsNotLoadedError(RuntimeError):
    """Raised when a function needs the vault but load_secrets() wasn't called yet."""


_state = {"master_seed": None, "hmac_secret": None, "aes_key": None}


# ── PBKDF2 passphrase-based file encryption ──────────────────────────────────
def _derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256, 200k iterations -> 32-byte AES key.

    NOTE: OWASP's current guidance for PBKDF2-HMAC-SHA256 is ~600,000
    iterations; 200k was reasonable a few years ago and is kept here to match
    the original system, but bump this if you re-key.
    """
    kdf = PBKDF2HMAC(
        algorithm=crypto_hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _encrypt_secret_file(data: bytes, passphrase: str, filepath: str):
    salt  = secrets.token_bytes(16)
    key   = _derive_key_from_passphrase(passphrase, salt)
    nonce = secrets.token_bytes(12)
    ct    = AESGCM(key).encrypt(nonce, data, None)
    with open(filepath, "wb") as f:
        f.write(salt + nonce + ct)   # layout: [16B salt][12B nonce][ciphertext+tag]
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
    except AttributeError:
        pass


def _decrypt_secret_file(filepath: str, passphrase: str) -> bytes:
    with open(filepath, "rb") as f:
        raw = f.read()
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    key = _derive_key_from_passphrase(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ct, None)


def load_secrets(passphrase: str = None):
    """
    On first run: generates a random 64-bit seed, a 256-bit HMAC key, and a
    256-bit AES key, then encrypts all three under `passphrase`.
    On later runs: decrypts them with `passphrase`.

    If `passphrase` is None, prompts interactively (hidden input).
    Returns (master_seed, hmac_secret_bytes, aes_key_bytes) and stores them
    for get_master_seed()/get_hmac_secret()/get_aes_key() to use.
    """
    first_run = not os.path.exists(config.SEED_FILE)

    if first_run:
        print("\n🔐  FIRST RUN — creating encrypted secret vault")
        print("   Choose a strong passphrase. You will need it every session.")
        pw = passphrase or getpass.getpass("   Set passphrase: ")
        if passphrase is None:
            confirm = getpass.getpass("   Confirm passphrase: ")
            if pw != confirm:
                raise ValueError("Passphrases do not match. Restart and try again.")

        seed        = secrets.randbelow(2 ** 64)   # random per project instance, never hardcoded
        hmac_secret = secrets.token_bytes(32)
        aes_key     = secrets.token_bytes(32)

        _encrypt_secret_file(struct.pack("<Q", seed), pw, config.SEED_FILE)
        _encrypt_secret_file(hmac_secret,             pw, config.HMAC_SECRET_FILE)
        _encrypt_secret_file(aes_key,                 pw, config.AES_KEY_FILE)
        print(f"   ✅ Secrets encrypted → {config.SECRETS_DIR}/")
    else:
        pw = passphrase or getpass.getpass("\n🔐  Enter vault passphrase: ")
        try:
            seed        = struct.unpack("<Q", _decrypt_secret_file(config.SEED_FILE, pw))[0]
            hmac_secret = _decrypt_secret_file(config.HMAC_SECRET_FILE, pw)
            aes_key     = _decrypt_secret_file(config.AES_KEY_FILE, pw)
        except FileNotFoundError as e:
            raise ValueError(
                f"Secret vault is partially missing ({e.filename}) — "
                f"this is NOT a wrong-passphrase error. Restore the file or "
                f"delete {config.SECRETS_DIR}/ to start a fresh vault."
            )
        except Exception:
            raise ValueError("Wrong passphrase or corrupted secret files.")

    _state["master_seed"]  = seed
    _state["hmac_secret"]  = hmac_secret
    _state["aes_key"]      = aes_key
    return seed, hmac_secret, aes_key


def _require_loaded():
    if _state["master_seed"] is None:
        raise SecretsNotLoadedError(
            "Secrets vault not unlocked yet — call crypto_vault.load_secrets() first."
        )


def get_master_seed() -> int:
    _require_loaded()
    return _state["master_seed"]


def get_hmac_secret() -> bytes:
    _require_loaded()
    return _state["hmac_secret"]


def get_aes_key() -> bytes:
    _require_loaded()
    return _state["aes_key"]


def replica_seed(replica_idx: int, master_seed: int = None) -> int:
    """SHA-256 derived per-replica seed, clipped to 31 bits for numpy's RNG."""
    if master_seed is None:
        master_seed = get_master_seed()
    raw = f"{master_seed}:replica:{replica_idx}".encode()
    return int(hashlib.sha256(raw).hexdigest(), 16) % (2 ** 31)


# ── AES-256-GCM encrypted image vault (the recoverable "original") ──────────
def encrypt_image(img_bgr, vault_name: str, aes_key: bytes = None) -> str:
    """Encrypt `img_bgr` (PNG-encoded) and save to VAULT_DIR/<vault_name>.enc.
    Returns vault_name (only the name is ever stored in the ledger, never the
    blob itself — keeps the ledger small regardless of how many images or how
    large they are).
    """
    if aes_key is None:
        aes_key = get_aes_key()
    ok, buf = cv2.imencode(".png", img_bgr)
    if not ok:
        raise ValueError("Failed to encode image to PNG bytes")
    plaintext  = buf.tobytes()
    nonce      = secrets.token_bytes(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    vault_path = os.path.join(config.VAULT_DIR, vault_name + ".enc")
    with open(vault_path, "wb") as f:
        f.write(nonce + ciphertext)
    try:
        os.chmod(vault_path, stat.S_IRUSR | stat.S_IWUSR)
    except AttributeError:
        pass
    return vault_name


def decrypt_image(vault_name: str, aes_key: bytes = None, ipfs_cid: str = None):
    """Read vault file and decrypt -> BGR numpy array.
    If the local .enc file is missing and `ipfs_cid` is given, pulls the
    encrypted blob from IPFS first (see integrations/ipfs_storage.py), then
    decrypts exactly as if it had been local all along.
    """
    if aes_key is None:
        aes_key = get_aes_key()
    vault_path = os.path.join(config.VAULT_DIR, vault_name + ".enc")
    if not os.path.exists(vault_path) and ipfs_cid:
        from integrations.ipfs_storage import download_from_ipfs
        print(f"ℹ️  Local vault file missing — pulling from IPFS [{ipfs_cid[:12]}...]")
        download_from_ipfs(ipfs_cid, vault_path)
    with open(vault_path, "rb") as f:
        raw = f.read()
    nonce, ct = raw[:12], raw[12:]
    plaintext = AESGCM(aes_key).decrypt(nonce, ct, None)
    arr = np.frombuffer(plaintext, dtype=np.uint8)
    return cv2.imdecode(arr, cv2.IMREAD_COLOR)


def recover_original(entry: dict, save_path: str = None):
    """Decrypt the vault original for a ledger entry. Called on tamper detection."""
    if "vault_name" not in entry:
        print("⚠️  No vault entry — this image was never registered.")
        return None
    try:
        img = decrypt_image(entry["vault_name"], ipfs_cid=entry.get("ipfs_cid"))
        if save_path:
            cv2.imwrite(save_path, img)
            print(f"   🔓 Original recovered → {save_path}")
        return img
    except Exception as e:
        print(f"   ⚠️  Recovery failed: {e}")
        return None
