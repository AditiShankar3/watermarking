This file is a merged representation of the entire codebase, combined into a single document by Repomix.

# File Summary

## Purpose
This file contains a packed representation of the entire repository's contents.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)

# Directory Structure
```
__init__.py
crypto_vault.py
ledger.py
metrics.py
pipeline.py
tamper_seal.py
visualizers.py
zero_watermark.py
```

# Files

## File: __init__.py
```python

```

## File: crypto_vault.py
```python
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
```

## File: ledger.py
```python
"""
ledger.py — HMAC-signed registration ledger, dual-hash permanent blacklist,
and a hash-chained + HMAC-signed forensic audit log.

All three write plain JSON to config.DATA_DIR; the signatures make silent
edits to those files detectable (not un-doable — see README's discussion of
externally-anchored checkpointing for that half of the story).
"""
import hashlib
import hmac as hmac_lib
import json
import os
from datetime import datetime

import imagehash
import numpy as np

import config
from watermark.crypto_vault import get_hmac_secret
from watermark.zero_watermark import get_phash


class LedgerTamperedError(Exception):
    pass


def get_image_hash(img_bgr) -> str:
    return hashlib.sha256(img_bgr.tobytes()).hexdigest()


def _sign_record(record: dict) -> str:
    payload = json.dumps(record, sort_keys=True).encode()
    return hmac_lib.new(get_hmac_secret(), payload, hashlib.sha256).hexdigest()


def _verify_record(record: dict):
    stored = record.pop("hmac_sig", None)
    if stored is None:
        raise LedgerTamperedError("Missing HMAC signature.")
    expected = _sign_record(dict(record))
    record["hmac_sig"] = stored
    if not hmac_lib.compare_digest(stored, expected):
        raise LedgerTamperedError("HMAC mismatch - record tampered.")


# ── Registration ledger ───────────────────────────────────────────────────────
def save_to_ledger(image_filename, img_bgr, M_buffer, W_key, P_anchors_all,
                    tamper_hash, vault_name, ipfs_cid=None):
    img_hash = get_image_hash(img_bgr)
    ph = str(get_phash(img_bgr))
    ledger = {}
    if os.path.exists(config.LEDGER_FILE):
        with open(config.LEDGER_FILE, "r") as f:
            ledger = json.load(f)
    record = {
        "image_filename": image_filename,
        "image_hash": img_hash,
        "image_phash": ph,
        "image_shape": list(img_bgr.shape),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tamper_hash": tamper_hash,
        "m_buffer": M_buffer.flatten().tolist(),
        "m_buffer_shape": list(M_buffer.shape),
        "master_key": W_key.tolist(),
        "anchors": P_anchors_all,
        "vault_name": vault_name,
        "ipfs_cid": ipfs_cid,
    }
    record["hmac_sig"] = _sign_record(dict(record))
    ledger[img_hash] = record
    with open(config.LEDGER_FILE, "w") as f:
        json.dump(ledger, f, indent=2)
    print(f"🔒 Ledger saved -> '{image_filename}'  [{img_hash[:8]}...]  "
          f"({len(ledger)} record(s) total)")
    return img_hash


def load_all_ledger_entries():
    if not os.path.exists(config.LEDGER_FILE):
        raise FileNotFoundError("Ledger not found - register at least one image first.")
    with open(config.LEDGER_FILE, "r") as f:
        ledger = json.load(f)
    required = {"tamper_hash", "m_buffer", "m_buffer_shape", "image_shape",
                "image_filename", "master_key", "anchors", "vault_name"}
    entries, skipped = [], 0
    for img_hash, record in ledger.items():
        missing = required - set(record.keys())
        if missing:
            print(f"⚠️  Skipping [{img_hash[:8]}...] - missing: {missing}")
            skipped += 1
            continue
        try:
            _verify_record(record)
        except LedgerTamperedError as e:
            print(f"⚠️  Skipping [{img_hash[:8]}...] - {e}")
            skipped += 1
            continue
        m_buf = np.array(record["m_buffer"], dtype=np.uint8).reshape(record["m_buffer_shape"])
        entries.append({
            "img_hash": img_hash,
            "image_filename": record["image_filename"],
            "image_shape": record["image_shape"],
            "timestamp": record["timestamp"],
            "tamper_hash": record["tamper_hash"],
            "M_buffer": m_buf,
            "W_key": np.array(record["master_key"], dtype=np.uint8),
            "P_anchors_all": record["anchors"],
            "vault_name": record["vault_name"],
            "image_phash": record.get("image_phash", ""),
            "ipfs_cid": record.get("ipfs_cid"),
        })
    if skipped:
        print(f"   ({skipped} record(s) skipped)")
    return entries


# ── Dual-hash permanent blacklist ────────────────────────────────────────────
def add_to_blacklist(img_bgr, filename, reason):
    img_hash = get_image_hash(img_bgr)
    ph = str(get_phash(img_bgr))
    blacklist = {}
    if os.path.exists(config.BLACKLIST_FILE):
        with open(config.BLACKLIST_FILE, "r") as f:
            blacklist = json.load(f)
    if img_hash not in blacklist:
        record = {
            "filename": filename,
            "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reason": reason,
            "img_hash": img_hash,
            "img_phash": ph,
        }
        record["hmac_sig"] = _sign_record(dict(record))
        blacklist[img_hash] = record
        with open(config.BLACKLIST_FILE, "w") as f:
            json.dump(blacklist, f, indent=2)
        print(f"   ⛔ Blacklisted [{img_hash[:8]}...]  pHash={ph}")
    else:
        print(f"   ⛔ Already blacklisted [{img_hash[:8]}...]")


def is_blacklisted(img_bgr):
    """Returns (True, record, match_type) or (False, None, None).
    match_type is "exact" (O(1) SHA-256) or "perceptual" (O(n) pHash scan —
    see README for the BK-tree indexing improvement at scale)."""
    if not os.path.exists(config.BLACKLIST_FILE):
        return False, None, None
    img_hash = get_image_hash(img_bgr)
    with open(config.BLACKLIST_FILE, "r") as f:
        blacklist = json.load(f)

    if img_hash in blacklist:
        record = blacklist[img_hash]
        try:
            _verify_record(record)
            return True, record, "exact"
        except LedgerTamperedError:
            pass

    suspect_ph = get_phash(img_bgr)
    for record in blacklist.values():
        stored_ph_str = record.get("img_phash", "")
        if not stored_ph_str:
            continue
        try:
            stored_ph = imagehash.hex_to_hash(stored_ph_str)
        except Exception:
            continue
        if (suspect_ph - stored_ph) <= config.PHASH_MAX_DIST:
            try:
                _verify_record(record)
                return True, record, "perceptual"
            except LedgerTamperedError:
                continue
    return False, None, None


def write_block_log(filename, img_bgr, block_reasons, nc, tamper_status):
    img_hash = get_image_hash(img_bgr)
    log = {}
    if os.path.exists(config.LOG_FILE):
        with open(config.LOG_FILE, "r") as f:
            log = json.load(f)
    key = f"{img_hash[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    log[key] = {
        "filename": filename,
        "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "img_hash": img_hash,
        "nc_score": round(nc, 4),
        "tamper": tamper_status,
        "reasons": block_reasons,
    }
    with open(config.LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)


# ── Forensic audit log (hash-chained + HMAC-signed) ──────────────────────────
def _audit_entry_hash(entry_core: dict) -> str:
    return hashlib.sha256(json.dumps(entry_core, sort_keys=True).encode()).hexdigest()


def log_audit_event(event_type, filename=None, img_bgr=None, decision=None, details=None):
    audit_log = []
    if os.path.exists(config.AUDIT_LOG_FILE):
        with open(config.AUDIT_LOG_FILE, "r") as f:
            audit_log = json.load(f)

    prev_hash = audit_log[-1]["entry_hash"] if audit_log else "0" * 64
    entry_core = {
        "seq": len(audit_log),
        "event_type": event_type,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "filename": filename,
        "image_hash": get_image_hash(img_bgr) if img_bgr is not None else None,
        "decision": decision,
        "details": details or {},
        "prev_hash": prev_hash,
    }
    entry_core["entry_hash"] = _audit_entry_hash(entry_core)
    entry = dict(entry_core)
    entry["hmac_sig"] = _sign_record(dict(entry))
    audit_log.append(entry)
    with open(config.AUDIT_LOG_FILE, "w") as f:
        json.dump(audit_log, f, indent=2)
    return entry


def verify_audit_chain():
    if not os.path.exists(config.AUDIT_LOG_FILE):
        return True, []
    with open(config.AUDIT_LOG_FILE, "r") as f:
        audit_log = json.load(f)

    problems = []
    expected_prev = "0" * 64
    for i, raw_entry in enumerate(audit_log):
        entry = dict(raw_entry)
        stored_hmac = entry.pop("hmac_sig", None)
        stored_entry_hash = entry.pop("entry_hash", None)

        if stored_entry_hash != _audit_entry_hash(entry):
            problems.append(f"Entry #{i} ({raw_entry.get('event_type')}): entry_hash mismatch.")

        recheck = dict(entry)
        recheck["entry_hash"] = stored_entry_hash
        if stored_hmac != _sign_record(recheck):
            problems.append(f"Entry #{i} ({raw_entry.get('event_type')}): HMAC signature invalid.")

        if entry.get("prev_hash") != expected_prev:
            problems.append(f"Entry #{i} ({raw_entry.get('event_type')}): chain broken "
                             f"(possible deletion/reordering).")
        expected_prev = stored_entry_hash

    return (len(problems) == 0), problems


def print_audit_trail(limit=None):
    if not os.path.exists(config.AUDIT_LOG_FILE):
        print("No audit log yet.")
        return
    with open(config.AUDIT_LOG_FILE, "r") as f:
        audit_log = json.load(f)
    ok, problems = verify_audit_chain()
    sep = "=" * 70
    print(sep)
    print(f"  FORENSIC AUDIT TRAIL   ({len(audit_log)} event(s))")
    print(f"  Chain integrity: {'INTACT' if ok else 'COMPROMISED'}")
    print(sep)
    for e in (audit_log[-limit:] if limit else audit_log):
        print(f"[{e['seq']:04d}] {e['timestamp']}  {e['event_type']:<30}  "
              f"file={e.get('filename')}  decision={e.get('decision')}")
        for k, v in (e.get("details") or {}).items():
            print(f"         - {k}: {v}")
    if not ok:
        print("\n⚠️  INTEGRITY PROBLEMS DETECTED:")
        for p in problems:
            print(f"   - {p}")
    print(sep)
```

## File: metrics.py
```python
"""
metrics.py — PSNR/SSIM/BER quality metrics, per-phase timing, empirical
complexity estimation, AND per-image CPU-time / peak-memory profiling for
registration (the resource-constrained-device numbers).
"""
import gc
import os
import threading
import time

import cv2
import numpy as np
import psutil
from skimage.metrics import structural_similarity as _ssim


# ── Quality metrics ───────────────────────────────────────────────────────────
def compute_psnr(img_a_bgr, img_b_bgr):
    if img_a_bgr.shape != img_b_bgr.shape:
        img_b_bgr = cv2.resize(img_b_bgr, (img_a_bgr.shape[1], img_a_bgr.shape[0]))
    return float(cv2.PSNR(img_a_bgr, img_b_bgr))


def compute_ssim(img_a_bgr, img_b_bgr):
    if img_a_bgr.shape != img_b_bgr.shape:
        img_b_bgr = cv2.resize(img_b_bgr, (img_a_bgr.shape[1], img_a_bgr.shape[0]))
    gray_a = cv2.cvtColor(img_a_bgr, cv2.COLOR_BGR2GRAY)
    gray_b = cv2.cvtColor(img_b_bgr, cv2.COLOR_BGR2GRAY)
    score, _ = _ssim(gray_a, gray_b, full=True)
    return float(score)


def compute_ber_from_accuracy(bit_accuracy_pct):
    return round(1.0 - (bit_accuracy_pct / 100.0), 4)


# ── Per-phase wall-clock timing ──────────────────────────────────────────────
class PhaseTimer:
    def __init__(self):
        self.times = {}
        self._t0_total = time.time()

    class _Ctx:
        def __init__(self, outer, name):
            self.outer, self.name = outer, name

        def __enter__(self):
            self._t0 = time.time()
            return self

        def __exit__(self, *exc):
            self.outer.times[self.name] = round(time.time() - self._t0, 4)

    def phase(self, name):
        return self._Ctx(self, name)

    def summary(self):
        self.times["total"] = round(time.time() - self._t0_total, 4)
        return dict(self.times)


def estimate_complexity(phase_times: dict, n_entries: int, image_shape: tuple):
    """Empirical scale-factor logging so complexity claims can be verified
    against real runs rather than asserted from Big-O alone."""
    h, w = image_shape[0], image_shape[1]
    pixel_count = h * w
    nc_time = phase_times.get("nc_verification", 0.0)
    total = phase_times.get("total", 0.0)
    time_per_entry = round(nc_time / n_entries, 5) if n_entries > 0 else None
    time_per_mpx = round(total / (pixel_count / 1_000_000), 4) if pixel_count > 0 else None
    return {
        "n_ledger_entries": n_entries,
        "pixel_count": pixel_count,
        "nc_verification_time_per_entry_s": time_per_entry,
        "total_time_per_megapixel_s": time_per_mpx,
        "complexity_notes": {
            "nc_verification": "O(n_entries * H * W) - linear scan over ledger; each "
                                "comparison re-runs DWT+DCT on the full image. See "
                                "README for a pHash-prefiltering fix.",
            "tamper_seal_check": "O(k) - k = fingerprint bit length (fixed, 256), "
                                  "independent of image size",
            "localisation": "O(H * W) - pixel-wise MAD over the full image, "
                             "reduced into a fixed 16x16 grid",
        },
    }


# ── CPU time + peak-memory profiling (registration only) ────────────────────
# Verification happens server-side and isn't the bottleneck you're optimizing
# for; registration is what would run on a resource-constrained edge device,
# so that's what this profiles.
_PROC = psutil.Process(os.getpid())


class PeakMemorySampler:
    """Background thread polls RSS every `interval` seconds and tracks the
    peak reached DURING this `with` block. `resource.ru_maxrss` is a
    process-lifetime high-water mark that never resets, so it would
    under-report every call after the first large one — this samples fresh
    per call instead."""

    def __init__(self, interval=0.02):
        self.interval = interval
        self._stop = threading.Event()
        self.peak_rss = 0
        self.baseline_rss = 0
        self._thread = None

    def _run(self):
        while not self._stop.is_set():
            rss = _PROC.memory_info().rss
            if rss > self.peak_rss:
                self.peak_rss = rss
            time.sleep(self.interval)

    def __enter__(self):
        gc.collect()
        self.baseline_rss = _PROC.memory_info().rss
        self.peak_rss = self.baseline_rss
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()
        rss = _PROC.memory_info().rss
        if rss > self.peak_rss:
            self.peak_rss = rss

    @property
    def peak_mb(self):
        return self.peak_rss / (1024 ** 2)

    @property
    def delta_mb(self):
        return (self.peak_rss - self.baseline_rss) / (1024 ** 2)


def profile_one_registration(img_bgr, master_seed=None) -> dict:
    """Runs ONLY the core algorithmic work of registration (YOLO ROI +
    DWT/DCT key generation + LSB seal + PNG encode) — deliberately excludes
    matplotlib diagnostics and any network call (IPFS/Drive/Mongo), since
    neither reflects what an edge deployment would actually pay for.
    """
    from watermark.zero_watermark import phase1_ai_roi_isolation, register_master_key_v3
    from watermark.tamper_seal import embed_tamper_signature

    gc.collect()
    cpu_before = _PROC.cpu_times()
    t0 = time.perf_counter()

    with PeakMemorySampler(interval=0.02) as sampler:
        _, M_binary, M_buffer = phase1_ai_roi_isolation(img_bgr)
        W_key, P_anchors_all, bg, LL3, dct_LL3 = register_master_key_v3(
            img_bgr, M_buffer, master_seed=master_seed)
        _, tamper_hash = embed_tamper_signature(img_bgr, master_seed=master_seed)
        ok, buf = cv2.imencode(".png", img_bgr)

    wall_s = time.perf_counter() - t0
    cpu_after = _PROC.cpu_times()
    cpu_s = (cpu_after.user - cpu_before.user) + (cpu_after.system - cpu_before.system)

    return {
        "wall_time_s": round(wall_s, 4),
        "cpu_time_s": round(cpu_s, 4),
        "cpu_utilization_pct": round(100 * cpu_s / wall_s, 1) if wall_s > 0 else None,
        "peak_rss_mb": round(sampler.peak_mb, 2),
        "delta_rss_mb": round(sampler.delta_mb, 2),
        "w_key_ones_pct": round(float(W_key.mean()) * 100, 2),
        "tamper_hash": tamper_hash[:16] + "...",
    }
```

## File: pipeline.py
```python
"""
pipeline.py — the two end-to-end flows: run_registration() (Person X) and
run_gateway() (the upload-time authenticity check). This is a straight port
of the notebook's Cell 7 / Cell 8 logic, with two changes:
  1. Images are loaded from a given file path instead of an interactive
     Colab/Jupyter upload widget (there's no notebook here to provide one).
  2. Registration diagnostics are one combined figure, skippable entirely
     via save_diagnostics=False (see visualizers.py).
Everything else — the check order, the block reasons, the recover-and-
deliver flow — is unchanged from the original.
"""
import os
import time
from datetime import datetime

import cv2
import imagehash

import config
from watermark.crypto_vault import encrypt_image, recover_original
from watermark.ledger import (
    get_image_hash, is_blacklisted, add_to_blacklist, write_block_log,
    load_all_ledger_entries, save_to_ledger, log_audit_event, _verify_record,
    _sign_record, LedgerTamperedError,
)
from watermark.metrics import PhaseTimer, compute_psnr, compute_ssim, compute_ber_from_accuracy, estimate_complexity
from watermark.tamper_seal import embed_tamper_signature, verify_tamper_signature, localise_tamper, classify_attack_type
from watermark.visualizers import show_registration_diagnostics, show_tamper_localisation
from watermark.zero_watermark import (
    phase1_ai_roi_isolation, register_master_key_v3, phase2_frequency_topology,
    extract_key_v3, verify_ownership, get_phash,
)


def load_image(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Not found: {path}")
    img = cv2.imread(path)
    if img is None:
        raise ValueError(f"Cannot decode: {path}")
    return img, os.path.basename(path)


def _append_result(record: dict):
    import json
    results = []
    if os.path.exists(config.RESULTS_FILE):
        with open(config.RESULTS_FILE, "r") as f:
            try:
                results = json.load(f)
            except Exception:
                results = []
    results.append(record)
    with open(config.RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=2)


# ── Post-delivery tamper lock (unchanged logic, ledger-file-backed) ─────────
def _log_delivery(img_bgr, filename):
    import json
    img_hash = get_image_hash(img_bgr)
    ph = str(get_phash(img_bgr))
    log = {}
    if os.path.exists(config.DELIVERY_LOG_FILE):
        with open(config.DELIVERY_LOG_FILE, "r") as f:
            log = json.load(f)
    record = {
        "filename": filename,
        "delivered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "img_hash": img_hash, "img_phash": ph, "status": "delivered_original",
    }
    record["hmac_sig"] = _sign_record(dict(record))
    log[img_hash] = record
    with open(config.DELIVERY_LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)
    print(f"   📋 Delivery logged [{img_hash[:8]}...]  (post-send tamper lock active)")


def _is_delivered_original(img_bgr):
    import json
    if not os.path.exists(config.DELIVERY_LOG_FILE):
        return False, None
    img_hash = get_image_hash(img_bgr)
    with open(config.DELIVERY_LOG_FILE, "r") as f:
        log = json.load(f)
    if img_hash in log:
        record = log[img_hash]
        try:
            _verify_record(record)
            return True, record
        except LedgerTamperedError:
            pass
    return False, None


def _is_tampered_delivery(img_bgr):
    import json
    if not os.path.exists(config.DELIVERY_LOG_FILE):
        return False, None, None
    img_hash = get_image_hash(img_bgr)
    suspect_ph = get_phash(img_bgr)
    with open(config.DELIVERY_LOG_FILE, "r") as f:
        log = json.load(f)
    for key, record in log.items():
        if key == img_hash:
            continue
        stored_ph_str = record.get("img_phash", "")
        if not stored_ph_str:
            continue
        try:
            stored_ph = imagehash.hex_to_hash(stored_ph_str)
        except Exception:
            continue
        dist = suspect_ph - stored_ph
        if dist <= config.PHASH_MAX_DIST:
            try:
                _verify_record(record)
                return True, record, dist
            except LedgerTamperedError:
                continue
    return False, None, None


def deliver_recovered_original(entry, suspect_filename):
    print("\n🔓  Recovering original from encrypted vault ...")
    temp_path = os.path.join(config.RECOVERED_DIR, "_temp_recovered.png")
    recovered = recover_original(entry, save_path=temp_path)
    if recovered is None:
        print("   ⚠️  Vault decryption failed. Cannot recover.")
        return None

    print("   🔏  Embedding post-delivery tamper seal ...")
    delivered_signed, _ = embed_tamper_signature(recovered)
    base = os.path.splitext(suspect_filename)[0]
    delivery_name = f"recovered_{base}.png"
    delivery_path = os.path.join(config.RECOVERED_DIR, delivery_name)
    cv2.imwrite(delivery_path, delivered_signed)
    print(f"   ✅  Delivered sealed original -> {delivery_path}")

    _log_delivery(delivered_signed, delivery_name)
    log_audit_event("RECOVERY_DELIVERED", filename=suspect_filename,
                     img_bgr=delivered_signed, decision="DELIVERED",
                     details={"delivery_name": delivery_name})
    if os.path.exists(temp_path):
        os.remove(temp_path)
    return delivery_path


# ── ▶ REGISTRATION (Person X) ────────────────────────────────────────────────
def run_registration(image_path: str, save_diagnostics: bool = True, backup_ipfs: bool = False):
    img, filename = load_image(image_path)
    print(f"\n📸  Registering: {filename}")

    flagged, bl_record, match_type = is_blacklisted(img)
    if flagged:
        match_desc = ("exact pixel match" if match_type == "exact"
                      else f"perceptual match (pHash dist <= {config.PHASH_MAX_DIST})")
        print(f"\n⛔  REGISTRATION REFUSED - blacklisted ({match_desc}), "
              f"first blocked {bl_record['blocked_at']}: {bl_record['reason']}")
        log_audit_event("REGISTRATION_REFUSED_BLACKLISTED", filename=filename, img_bgr=img,
                         decision="REFUSED", details={"match_type": match_type, "reason": bl_record["reason"]})
        return None, None

    print("\nPhase 1 - YOLO ROI masking ...")
    img_rgb, M_binary, M_buffer = phase1_ai_roi_isolation(img)

    print("Phase 2-5 - Frequency topology + key generation ...")
    W_key, P_anchors_all, bg, LL3, dct_LL3 = register_master_key_v3(img, M_buffer)

    if save_diagnostics:
        import cv2 as _cv2
        gray_bg_for_plot = _cv2.cvtColor(
            __import__("watermark.zero_watermark", fromlist=["robust_prefilter_v2"]).robust_prefilter_v2(img),
            _cv2.COLOR_BGR2GRAY).astype("float64")
        show_registration_diagnostics(img_rgb, M_binary, M_buffer, gray_bg_for_plot,
                                       LL3, dct_LL3, P_anchors_all, W_key)

    print("\nEmbedding scattered tamper seal ...")
    img_signed, tamper_hash = embed_tamper_signature(img)

    print("Encrypting original -> vault ...")
    base_name = os.path.splitext(filename)[0]
    vault_name = encrypt_image(img, vault_name=base_name)

    img_hash = save_to_ledger(filename, img, M_buffer, W_key, P_anchors_all, tamper_hash, vault_name)

    if backup_ipfs:
        from integrations.ipfs_storage import backup_to_ipfs_async
        vault_path = os.path.join(config.VAULT_DIR, vault_name + ".enc")
        backup_to_ipfs_async(vault_path, img_hash)

    signed_name = base_name + "_signed" + os.path.splitext(filename)[1]
    signed_path = os.path.join(config.SIGNED_DIR, signed_name)
    cv2.imwrite(signed_path, img_signed)

    print(f"\n✅  REGISTRATION COMPLETE")
    print(f"   Signed copy : {signed_path}  <- send this to Person Y")
    print(f"   Vault file  : {config.VAULT_DIR}/{vault_name}.enc")
    print(f"   Key balance : {W_key.mean() * 100:.1f}% ones")

    log_audit_event("REGISTRATION", filename=filename, img_bgr=img, decision="REGISTERED",
                     details={"vault_name": vault_name, "tamper_hash": tamper_hash[:16]})
    return img, filename


# ── ▶ CONTENT AUTHENTICITY GATEWAY (verification) ────────────────────────────
def run_gateway(image_path: str, platform: str = "police_portal", auto_recover: bool = False):
    if platform not in config.PLATFORMS:
        raise ValueError(f"Choose from: {list(config.PLATFORMS.keys())}")
    cfg = config.PLATFORMS[platform]

    suspect_img, suspect_filename = load_image(image_path)
    print(f"\n⏳  Gateway checking: {suspect_filename}  [{cfg['icon']} {cfg['name']}]")
    pt = PhaseTimer()
    t_start = time.time()

    # Post-delivery checks
    is_clean, dl_record = _is_delivered_original(suspect_img)
    if is_clean:
        print(f"\n✅  ALLOW - verified clean delivered original ({dl_record['filename']})")
        log_audit_event("ALLOW_DELIVERED_ORIGINAL", filename=suspect_filename, img_bgr=suspect_img,
                         decision="ALLOW", details={"platform": platform, "delivered_as": dl_record["filename"]})
        return "ALLOW"

    is_tampered_delivery, td_record, ph_dist = _is_tampered_delivery(suspect_img)
    if is_tampered_delivery:
        print(f"\n⛔  BLOCK - edited version of a previously delivered original "
              f"(pHash dist={ph_dist}, orig={td_record['filename']})")
        add_to_blacklist(suspect_img, suspect_filename,
                          "Post-delivery tampering: edited version of delivered original")
        write_block_log(suspect_filename, suspect_img, ["Post-delivery tampering"], 0.0, "TAMPERED POST-DELIVERY")
        log_audit_event("BLOCK_POST_DELIVERY_TAMPER", filename=suspect_filename, img_bgr=suspect_img,
                         decision="BLOCK", details={"platform": platform, "phash_dist": ph_dist,
                                                     "original_delivery": td_record["filename"]})
        return "BLOCK"

    # Exact registered original?
    try:
        entries = load_all_ledger_entries()
        suspect_hash = get_image_hash(suspect_img)
        orig_match = next((e for e in entries if e["img_hash"] == suspect_hash), None)
    except FileNotFoundError as e:
        print(f"❌  {e}")
        return "ERROR"

    if orig_match is not None:
        print(f"\n✅  ALLOW - exact match to registered original "
              f"({orig_match['image_filename']}, registered {orig_match['timestamp']})")
        _append_result({
            "filename": suspect_filename, "image_shape": list(suspect_img.shape),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "decision": "ALLOW", "tamper_status": "INTACT", "seal_intact": True,
            "content_intact": True, "nc_score": 1.0, "bit_accuracy": 100.0, "ber": 0.0,
            "n_tampered_cells": 0, "resized": False, "block_reasons": [],
            "attack_type": "None (Untampered)", "recovery_attempted": False,
            "recovery_success": False, "recovery_time_s": None,
            "check_time_s": round(time.time() - t_start, 3),
        })
        log_audit_event("ALLOW_EXACT_MATCH", filename=suspect_filename, img_bgr=suspect_img,
                         decision="ALLOW", details={"platform": platform, "registered_as": orig_match["image_filename"]})
        return "ALLOW"

    # Blacklist
    flagged, bl_record, match_type = is_blacklisted(suspect_img)
    if flagged:
        print(f"\n⛔  BLOCK - permanently blacklisted ({match_type} match, "
              f"first blocked {bl_record['blocked_at']}): {bl_record['reason']}")
        _append_result({
            "filename": suspect_filename, "image_shape": list(suspect_img.shape),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "decision": "BLOCK", "tamper_status": "BLACKLISTED", "seal_intact": None,
            "content_intact": None, "nc_score": 0.0, "bit_accuracy": 0.0, "ber": 1.0,
            "n_tampered_cells": 0, "resized": False, "block_reasons": ["blacklisted"],
            "attack_type": "N/A (Pre-blacklisted)", "recovery_attempted": False,
            "recovery_success": False, "recovery_time_s": None,
            "check_time_s": round(time.time() - t_start, 3),
        })
        log_audit_event("BLOCK_BLACKLISTED", filename=suspect_filename, img_bgr=suspect_img,
                         decision="BLOCK", details={"platform": platform, "match_type": match_type,
                                                     "reason": bl_record["reason"]})
        return "BLOCK"

    # NC ownership scan over the full ledger
    best_nc, best_acc, best_entry = 0.0, 0.0, None
    second_best_nc = 0.0
    with pt.phase("nc_verification"):
        for entry in entries:
            eh, ew = entry["image_shape"][:2]
            img_r = cv2.resize(suspect_img, (ew, eh)) if suspect_img.shape[:2] != (eh, ew) else suspect_img
            key_ext = extract_key_v3(img_r, entry["M_buffer"], entry["P_anchors_all"],
                                      entry["W_key"], tuple(entry["image_shape"]))
            nc, acc, _ = verify_ownership(entry["W_key"], key_ext)
            if nc > best_nc:
                second_best_nc = best_nc
                best_nc, best_acc, best_entry = nc, acc, entry
            elif nc > second_best_nc:
                second_best_nc = nc

    if best_entry is None:
        print("❌  No matching registered image.")
        return "BLOCK"

    eh, ew = best_entry["image_shape"][:2]
    img_r = cv2.resize(suspect_img, (ew, eh)) if suspect_img.shape[:2] != (eh, ew) else suspect_img.copy()

    with pt.phase("tamper_seal_check"):
        tamper = verify_tamper_signature(img_r, best_entry["tamper_hash"], tuple(best_entry["image_shape"]))
        tamper_ok = tamper["seal_intact"]

    n_tampered, heatmap_path, recovered_orig = 0, None, None
    tamper_map, mad_grid = None, None
    if not tamper_ok:
        with pt.phase("localisation"):
            print("\n🔬  Running tamper localisation ...")
            recovered_orig = recover_original(best_entry)
            if recovered_orig is not None:
                tamper_map, mad_grid, cell_h, cell_w = localise_tamper(recovered_orig, suspect_img)
                n_tampered = int(tamper_map.sum())
                heatmap_path = show_tamper_localisation(
                    recovered_orig, suspect_img, tamper_map, mad_grid, cell_h, cell_w,
                    save_name=f"{os.path.splitext(suspect_filename)[0]}_heatmap.png")

    ownership_ok = best_nc >= cfg["nc_threshold"]
    block_reasons = []
    if not tamper_ok:
        block_reasons.append(f"Tamper seal broken - {tamper['detail']}")
    if not ownership_ok:
        block_reasons.append(f"NC score {best_nc:.4f} below threshold {cfg['nc_threshold']}")
    decision = "BLOCK" if block_reasons else "ALLOW"

    psnr_val, ssim_val = None, None
    if recovered_orig is not None:
        psnr_val = compute_psnr(recovered_orig, img_r)
        ssim_val = compute_ssim(recovered_orig, img_r)

    attack_label, attack_detail, _ = classify_attack_type(
        tamper, tamper_map, mad_grid, best_nc, cfg["nc_threshold"],
        second_best_nc=second_best_nc, psnr_val=psnr_val, ssim_val=ssim_val)

    ber_val = compute_ber_from_accuracy(best_acc)
    phase_times = pt.summary()
    complexity_info = estimate_complexity(phase_times, len(entries), suspect_img.shape)

    if decision == "BLOCK":
        add_to_blacklist(img_r, suspect_filename, block_reasons[0] if block_reasons else "Check failed")
        write_block_log(suspect_filename, img_r, block_reasons, best_nc, tamper["status"])

    log_audit_event(decision, filename=suspect_filename, img_bgr=img_r, decision=decision,
                     details={"platform": platform, "nc_score": round(float(best_nc), 4),
                              "bit_accuracy": round(float(best_acc), 2), "ber": ber_val,
                              "seal_intact": bool(tamper_ok), "block_reasons": block_reasons,
                              "attack_type": attack_label})

    verdict = "🚫 BLOCK" if decision == "BLOCK" else "✅ ALLOW"
    print(f"\n{verdict}  |  NC={best_nc:.4f} (threshold {cfg['nc_threshold']})  "
          f"|  seal_intact={tamper_ok}  |  attack_type={attack_label}")
    if heatmap_path:
        print(f"  heatmap: {heatmap_path}")
    if block_reasons:
        for i, r in enumerate(block_reasons, 1):
            print(f"  reason {i}: {r}")

    result_record = {
        "filename": suspect_filename, "image_shape": list(suspect_img.shape),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "decision": decision, "tamper_status": tamper["status"],
        "seal_intact": bool(tamper["seal_intact"]),
        "content_intact": bool(tamper["content_intact"]) if tamper.get("content_intact") is not None else None,
        "nc_score": round(float(best_nc), 4), "second_best_nc": round(float(second_best_nc), 4),
        "bit_accuracy": round(float(best_acc), 2), "ber": ber_val,
        "psnr_db": round(psnr_val, 2) if psnr_val is not None else None,
        "ssim": round(ssim_val, 4) if ssim_val is not None else None,
        "n_tampered_cells": int(n_tampered), "resized": bool(tamper.get("resized", False)),
        "block_reasons": block_reasons, "attack_type": attack_label, "attack_detail": attack_detail,
        "phase_times_s": phase_times, "recovery_attempted": False, "recovery_success": False,
        "recovery_time_s": None, "check_time_s": phase_times.get("total", 0),
        "computational_complexity": complexity_info,
    }

    if decision == "BLOCK":
        do_recover = auto_recover
        if not auto_recover:
            try:
                do_recover = input("  ▶ Recover and deliver original? [y/N]: ").strip().lower() == "y"
            except EOFError:
                do_recover = False
        result_record["recovery_attempted"] = do_recover
        if do_recover:
            t_rec = time.time()
            delivery_path = deliver_recovered_original(best_entry, suspect_filename)
            result_record["recovery_time_s"] = round(time.time() - t_rec, 3)
            result_record["recovery_success"] = delivery_path is not None
            if delivery_path:
                print(f"  ✅ recovered & delivered -> {delivery_path}")

    _append_result(result_record)
    return decision
```

## File: tamper_seal.py
```python
"""
tamper_seal.py — the fragile half of the two-tier design: a SHA-256 hash of
the pixel content, embedded 1 bit per scattered pixel (blue-channel LSB),
at positions only derivable from the secret MASTER_SEED. Anyone without the
seed can't locate the seal to selectively preserve it during an edit.
"""
import hashlib
import hmac as hmac_lib

import cv2
import numpy as np

import config
from watermark.crypto_vault import get_master_seed


# ── Scattered LSB seal ────────────────────────────────────────────────────────
def _get_lsb_positions(img_bgr, n_bits, master_seed=None):
    """Deterministic (same seed -> same positions), scattered across the
    whole image — not fixed top-left, so an attacker can't crop it out
    without knowing the seed."""
    if master_seed is None:
        master_seed = get_master_seed()
    h, w = img_bgr.shape[:2]
    total_px = h * w
    rng = np.random.default_rng(
        int(hashlib.sha256(f"lsb_positions:{master_seed}".encode()).hexdigest(), 16) % (2 ** 31)
    )
    return rng.choice(total_px, size=n_bits, replace=False)


def _embed_lsb(img_bgr, bits, master_seed=None):
    out = img_bgr.copy()
    h, w = out.shape[:2]
    positions = _get_lsb_positions(img_bgr, len(bits), master_seed)
    flat_blue = out[:, :, 0].flatten().astype(np.int32)
    for pos, bit in zip(positions, bits):
        flat_blue[pos] = (flat_blue[pos] & 0b11111110) | int(bit)
    out[:, :, 0] = flat_blue.reshape(h, w).astype(np.uint8)
    return out


def _extract_lsb(img_bgr, n_bits, master_seed=None):
    positions = _get_lsb_positions(img_bgr, n_bits, master_seed)
    flat_blue = img_bgr[:, :, 0].flatten()
    return [int(flat_blue[pos]) & 1 for pos in positions]


def _hash_to_bits(hash_hex):
    bits = []
    for ch in hash_hex:
        v = int(ch, 16)
        bits.extend([(v >> i) & 1 for i in range(3, -1, -1)])
    return bits


def _bits_to_hash(bits):
    bits = bits[:len(bits) - (len(bits) % 4)]
    return "".join(
        format((bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3], "x")
        for i in range(0, len(bits), 4)
    )


def embed_tamper_signature(img_bgr, master_seed=None):
    """SHA-256 of pixels -> embed at MASTER_SEED-scattered positions.
    Returns (signed_image, tamper_hash)."""
    h = hashlib.sha256(img_bgr.tobytes()).hexdigest()
    signed = _embed_lsb(img_bgr, _hash_to_bits(h), master_seed)
    return signed, h


def verify_tamper_signature(suspect_bgr, registered_hash, original_shape, master_seed=None):
    """Resolution-aware: a resized copy will always fail a raw pixel-hash
    check, so resize is reported separately from genuine tampering rather
    than conflated with it."""
    susp_h, susp_w = suspect_bgr.shape[:2]
    orig_h, orig_w = original_shape[:2]
    resized = (susp_h != orig_h or susp_w != orig_w)

    suspect_hash = hashlib.sha256(suspect_bgr.tobytes()).hexdigest()
    content_intact = hmac_lib.compare_digest(suspect_hash, registered_hash)

    check_img = cv2.resize(suspect_bgr, (orig_w, orig_h)) if resized else suspect_bgr
    extracted_hash = _bits_to_hash(_extract_lsb(check_img, 256, master_seed))
    seal_intact = hmac_lib.compare_digest(extracted_hash, registered_hash)

    if resized:
        if seal_intact:
            status = "UNTAMPERED (resized copy)"
            detail = f"Resolution changed ({susp_w}x{susp_h} vs {orig_w}x{orig_h}) but LSB seal intact."
        else:
            status = "TAMPERED - seal destroyed (resized)"
            detail = "Resolution changed AND seal overwritten. Likely re-encoded after editing."
        return {"status": status, "detail": detail,
                "content_intact": False, "seal_intact": seal_intact, "resized": True}

    if content_intact:
        status, detail = "UNTAMPERED", "Pixel content matches registered original exactly."
    elif seal_intact:
        status, detail = "TAMPERED - seal survived", "Pixel content modified but LSB seal still readable."
    else:
        status, detail = "TAMPERED - seal destroyed", "Pixel content modified AND LSB seal overwritten."
    return {"status": status, "detail": detail,
            "content_intact": content_intact, "seal_intact": seal_intact, "resized": False}


# ── MAD-grid tamper localisation ─────────────────────────────────────────────
def localise_tamper(original_bgr, suspect_bgr, grid=config.TAMPER_BLOCKS,
                     threshold_pct=15, abs_floor=config.MAD_ABS_FLOOR):
    """16x16 mean-absolute-difference grid. A cell is flagged only if its MAD
    is BOTH in the top threshold_pct% AND above abs_floor — the absolute
    floor keeps clean images from flagging spurious cells just because
    *something* has to be the top percentile."""
    oh, ow = original_bgr.shape[:2]
    susp_r = cv2.resize(suspect_bgr, (ow, oh)) if suspect_bgr.shape[:2] != (oh, ow) else suspect_bgr.copy()
    diff = np.abs(original_bgr.astype(np.float32) - susp_r.astype(np.float32)).mean(axis=2)
    cell_h, cell_w = oh // grid, ow // grid
    mad_grid = np.array(
        [[diff[gr * cell_h:(gr + 1) * cell_h, gc * cell_w:(gc + 1) * cell_w].mean()
          for gc in range(grid)] for gr in range(grid)],
        dtype=np.float32)
    pct_cutoff = np.percentile(mad_grid, 100 - threshold_pct)
    tamper_map = (mad_grid >= pct_cutoff) & (mad_grid >= abs_floor)
    return tamper_map, mad_grid, cell_h, cell_w


# ── Heuristic attack-type classifier ─────────────────────────────────────────
# CALIBRATION NOTE: the thresholds below were anchored on a small labeled
# sample (documented in the original notebook as exactly two examples).
# Treat them as a reasonable starting boundary, not validated ground truth —
# re-check and tighten as you collect more labeled attack samples, ideally
# including images that were never registered at all (see README).
def classify_attack_type(tamper, tamper_map, mad_grid, best_nc, nc_threshold,
                          second_best_nc=None, psnr_val=None, ssim_val=None,
                          collusion_margin=0.05,
                          ssim_compression_floor=0.90,
                          ssim_ai_ceiling=0.85,
                          psnr_ai_ceiling=28.0,
                          mad_quant_ceiling=12.0,
                          mad_splice_floor=20.0):
    """Returns (attack_label, attack_detail, confidence)."""
    resized = tamper.get("resized", False)
    seal_intact = tamper.get("seal_intact", False)

    if resized and seal_intact:
        return ("None (Benign Transformation)",
                "Resolution changed but LSB seal intact - legitimate resize, no attack.",
                "heuristic")
    if (not resized) and tamper.get("content_intact", False):
        return ("None (Untampered)", "Exact pixel match to registered original.", "heuristic")

    if tamper_map is None or mad_grid is None:
        return ("Unclassified Tampering",
                "Seal broken but tamper-map unavailable for finer classification.",
                "heuristic")

    total_cells = tamper_map.size
    n_tampered = int(tamper_map.sum())
    tamper_pct = (n_tampered / total_cells) * 100
    flagged_vals = mad_grid[tamper_map] if n_tampered > 0 else np.array([0.0])
    mean_mad_flag = float(flagged_vals.mean())

    if resized and not seal_intact:
        return ("Resize + Re-encoding Attack",
                f"Resolution changed AND seal destroyed - image was resized "
                f"and/or resaved after editing ({tamper.get('detail', '')}).",
                "heuristic")

    if (second_best_nc is not None and (best_nc - second_best_nc) < collusion_margin
            and best_nc < nc_threshold + 0.10):
        return ("Possible Collusion Attack",
                f"Structural fingerprint sits nearly equidistant between two "
                f"registered originals (NC {best_nc:.4f} vs {second_best_nc:.4f}).",
                "heuristic")

    if ssim_val is not None and psnr_val is not None:
        if ssim_val < ssim_ai_ceiling or psnr_val < psnr_ai_ceiling:
            return ("AI Regeneration / Pixel-Laundering Attack",
                    f"Global fidelity collapsed (SSIM={ssim_val:.3f}, PSNR={psnr_val:.2f} dB) "
                    f"relative to the recovered original.",
                    "heuristic")
        if ssim_val >= ssim_compression_floor and mean_mad_flag < mad_quant_ceiling:
            return ("JPEG Recompression / Quantization Attack",
                    f"Global structure preserved (SSIM={ssim_val:.3f}, PSNR={psnr_val:.2f} dB) "
                    f"with only low-magnitude flagged cells (mean MAD={mean_mad_flag:.1f}).",
                    "heuristic")

    if tamper_pct <= 20 and mean_mad_flag >= mad_splice_floor:
        return ("Localized Splicing / Object Insertion-Removal",
                f"Tampering concentrated in {tamper_pct:.1f}% of the grid with "
                f"high contrast (mean flagged MAD={mean_mad_flag:.1f}).",
                "heuristic")

    return ("Unclassified Tampering",
            f"Seal broken, {tamper_pct:.1f}% of grid flagged (mean flagged MAD={mean_mad_flag:.1f}"
            + (f", SSIM={ssim_val:.3f}, PSNR={psnr_val:.2f} dB" if ssim_val is not None else "")
            + ") - pattern doesn't cleanly match a known category; needs manual review.",
            "heuristic")
```

## File: visualizers.py
```python
"""
visualizers.py — plotting only. Registration diagnostics are ONE combined
figure (not four separate PNGs) and are entirely optional per-run via
`save_diagnostics=False` in pipeline.run_registration — batch/profiling runs
should always pass False so matplotlib rendering never pollutes timing runs.
"""
import os

import cv2
import matplotlib
import numpy as np

import config

# Headless-safe: only switch backend if no display is available.
try:
    import matplotlib.pyplot as plt
    if not os.environ.get("DISPLAY") and os.name != "nt":
        matplotlib.use("Agg")
except Exception:
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt


def show_registration_diagnostics(img_rgb, M_binary, M_buffer, gray_bg, LL3, dct_LL3,
                                   P_anchors_all, W_key, save_name="registration_diagnostics.png"):
    """Replaces the original four separate figures (ROI mask, frequency
    topology, anchor map, binary key) with one combined figure per
    registration, to cut down on file clutter."""
    fig = plt.figure(figsize=(18, 12))
    gs = fig.add_gridspec(3, 3, height_ratios=[1, 1, 0.4])

    ax = fig.add_subplot(gs[0, 0]); ax.imshow(img_rgb); ax.set_title("Original"); ax.axis("off")
    ax = fig.add_subplot(gs[0, 1]); ax.imshow(M_binary, cmap="gray", vmin=0, vmax=255)
    ax.set_title("YOLO mask"); ax.axis("off")
    ax = fig.add_subplot(gs[0, 2]); ax.imshow(M_buffer, cmap="gray", vmin=0, vmax=255)
    ax.set_title("Safety buffer"); ax.axis("off")

    ax = fig.add_subplot(gs[1, 0]); ax.imshow(gray_bg, cmap="gray"); ax.set_title("Background"); ax.axis("off")
    ax = fig.add_subplot(gs[1, 1]); ax.imshow(LL3, cmap="gray"); ax.set_title("LL3 - DWTx3"); ax.axis("off")
    ax = fig.add_subplot(gs[1, 2])
    ax.imshow(img_rgb)
    ya = [(c[0] * 8) + 16 for c in P_anchors_all[0]]
    xa = [(c[1] * 8) + 16 for c in P_anchors_all[0]]
    ax.scatter(xa, ya, c="lime", s=25, marker="s", edgecolors="black", linewidths=0.4)
    ax.set_title("Anchor map (replica 0)"); ax.axis("off")

    ax = fig.add_subplot(gs[2, :])
    ax.imshow([W_key], cmap="Greys", aspect="auto")
    ones = W_key.mean() * 100
    ax.set_title(f"256-bit master key | {ones:.1f}% ones "
                 f"({'balanced' if 40 < ones < 60 else 'CHECK SEED'})", fontsize=10)
    ax.set_yticks([])

    plt.suptitle("Registration Diagnostics", fontweight="bold", y=1.01)
    plt.tight_layout()
    path = os.path.join(config.DIAGNOSTICS_DIR, save_name)
    fig.savefig(path, bbox_inches="tight", dpi=120)
    plt.close(fig)
    print(f"   Diagnostics -> {path}")
    return path


def show_tamper_localisation(original_bgr, suspect_bgr, tamper_map, mad_grid,
                              cell_h, cell_w, save_name="tamper_heatmap.png"):
    import matplotlib.patches as patches

    oh, ow = original_bgr.shape[:2]
    orig_rgb = cv2.cvtColor(original_bgr, cv2.COLOR_BGR2RGB)
    susp_r = cv2.resize(suspect_bgr, (ow, oh)) if suspect_bgr.shape[:2] != (oh, ow) else suspect_bgr.copy()
    susp_rgb = cv2.cvtColor(susp_r, cv2.COLOR_BGR2RGB)
    grid = tamper_map.shape[0]
    n_t = int(tamper_map.sum())

    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    axes[0].imshow(orig_rgb); axes[0].set_title("Recovered Original", fontsize=13, fontweight="bold"); axes[0].axis("off")
    axes[1].imshow(susp_rgb)
    axes[1].set_title(f"Suspect - {n_t} flagged region(s)" if n_t > 0 else "Suspect - no regions flagged",
                       fontsize=13, fontweight="bold", color="crimson" if n_t > 0 else "green")
    axes[1].axis("off")
    for gr in range(grid):
        for gc in range(grid):
            if tamper_map[gr, gc]:
                axes[1].add_patch(patches.Rectangle((gc * cell_w, gr * cell_h), cell_w, cell_h,
                                                      linewidth=2, edgecolor="red", facecolor="red", alpha=0.25))
                axes[1].add_patch(patches.Rectangle((gc * cell_w, gr * cell_h), cell_w, cell_h,
                                                      linewidth=2, edgecolor="red", facecolor="none"))
    im = axes[2].imshow(mad_grid, cmap="hot", interpolation="nearest")
    axes[2].set_title(f"MAD heatmap (floor={config.MAD_ABS_FLOOR})", fontsize=13, fontweight="bold")
    plt.colorbar(im, ax=axes[2], label="Mean abs pixel diff")
    plt.suptitle("TAMPER LOCALISATION REPORT", fontsize=15, fontweight="bold", color="crimson", y=1.01)
    plt.tight_layout()
    save_path = os.path.join(config.HEATMAPS_DIR, save_name)
    plt.savefig(save_path, bbox_inches="tight", dpi=150)
    plt.close()
    print(f"   Heatmap saved -> {save_path}")
    return save_path
```

## File: zero_watermark.py
```python
"""
zero_watermark.py — the structural, "zero"-watermark half of the system.

Nothing is embedded in the image here: a 256-bit fingerprint is *derived*
from stable background DCT coefficients (selected via YOLO segmentation +
a 3-level Haar DWT), stored in the ledger, and recomputed at verification
time for comparison. This is what survives benign JPEG recompression —
the complementary fragile seal lives in tamper_seal.py.
"""
import hashlib

import cv2
import numpy as np
import pywt
import imagehash
from PIL import Image as PILImage
from ultralytics import YOLO

import config

# ── YOLO model, loaded once and cached ───────────────────────────────────────
_YOLO_MODEL = None


def get_yolo():
    global _YOLO_MODEL
    if _YOLO_MODEL is None:
        _YOLO_MODEL = YOLO("yolov8n-seg.pt", verbose=False)
        print("   YOLO model loaded (cached for process lifetime)")
    return _YOLO_MODEL


def phase1_ai_roi_isolation(img_bgr, buffer_iterations=3):
    """YOLO instance segmentation -> background mask M_buffer.
    Classes excluded from "safe background": person, bicycle, car, motorcycle,
    bus, truck (COCO ids 0,1,2,3,5,7) — i.e. anything that moves.
    """
    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    h, w = img_bgr.shape[:2]
    model = get_yolo()
    results = model(img_bgr, device=config.YOLO_DEVICE, verbose=False)
    target_classes = [0, 1, 2, 3, 5, 7]
    roi_mask = np.zeros((h, w), dtype=bool)
    for result in results:
        if result.masks is not None:
            for mask, box in zip(result.masks.data, result.boxes):
                if int(box.cls[0]) in target_classes:
                    m = mask.cpu().numpy()
                    m_r = cv2.resize(m, (w, h), interpolation=cv2.INTER_NEAREST).astype(bool)
                    roi_mask = np.logical_or(roi_mask, m_r)
    M_binary = np.where(roi_mask, 0, 255).astype(np.uint8)
    kernel = np.ones((5, 5), np.uint8)
    M_buffer = cv2.erode(M_binary, kernel, iterations=buffer_iterations)
    return img_rgb, M_binary, M_buffer


def robust_prefilter_v2(img_bgr):
    bilateral = cv2.bilateralFilter(img_bgr, d=15, sigmaColor=80, sigmaSpace=80)
    return cv2.GaussianBlur(bilateral, (31, 31), sigmaX=10)


def _dct_blockwise(matrix, bs=4):
    h, w = matrix.shape
    h_c, w_c = (h // bs) * bs, (w // bs) * bs
    mat = matrix[:h_c, :w_c].astype(np.float32)
    out = np.zeros_like(mat)
    for r in range(0, h_c, bs):
        for c in range(0, w_c, bs):
            out[r:r + bs, c:c + bs] = cv2.dct(mat[r:r + bs, c:c + bs])
    return out


def phase2_frequency_topology(img_bgr, M_buffer, block_size=config.BLOCK_SIZE):
    clean = robust_prefilter_v2(img_bgr)
    gray = cv2.cvtColor(clean, cv2.COLOR_BGR2GRAY).astype(np.float64)
    bg = np.where(M_buffer == 255, gray, 0.0)
    LL1 = pywt.dwt2(bg, "haar")[0]
    LL2 = pywt.dwt2(LL1, "haar")[0]
    LL3 = pywt.dwt2(LL2, "haar")[0]
    return bg, LL3, _dct_blockwise(LL3, bs=block_size)


def phase3_collect_safe_blocks(dct_LL3, M_buffer, block_size=config.BLOCK_SIZE):
    """Blocks are "safe" only if their full-resolution footprint is entirely
    background (never touches a masked moving-object region)."""
    h_ll3, w_ll3 = dct_LL3.shape
    full_scale = block_size * 8
    safe_blocks = []
    for r in range(0, h_ll3 - block_size, block_size):
        for c in range(0, w_ll3 - block_size, block_size):
            fr, fc = r * 8, c * 8
            patch = M_buffer[fr:fr + full_scale, fc:fc + full_scale]
            if patch.shape == (full_scale, full_scale) and np.all(patch == 255):
                dc = dct_LL3[r:r + block_size, c:c + block_size][0, 0]
                safe_blocks.append({"r": r, "c": c, "dc": dc})
    return safe_blocks


def register_master_key_v3(original_bgr, M_buffer,
                            key_len=config.KEY_LEN, block_size=config.BLOCK_SIZE,
                            master_seed=None, n_replicas=config.N_REPLICAS,
                            pool_pct=config.POOL_PCT):
    """Derive the 256-bit structural fingerprint (majority vote across
    n_replicas independently-seeded anchor sets, for robustness)."""
    from watermark.crypto_vault import replica_seed
    if master_seed is None:
        from watermark.crypto_vault import get_master_seed
        master_seed = get_master_seed()

    bg, LL3, dct_LL3 = phase2_frequency_topology(original_bgr, M_buffer, block_size)
    safe_blocks = phase3_collect_safe_blocks(dct_LL3, M_buffer, block_size)
    if len(safe_blocks) < key_len:
        raise ValueError("Too few safe background blocks — try a different image "
                          "or relax the YOLO mask / buffer erosion.")

    dc_values = [b["dc"] for b in safe_blocks]
    global_median = np.median(dc_values)
    safe_blocks.sort(key=lambda b: b["dc"])
    pool_n = max(int(len(safe_blocks) * pool_pct), 1)
    pool_dark = safe_blocks[:pool_n]
    pool_bright = safe_blocks[-pool_n:]

    P_anchors_all = []
    for rep in range(n_replicas):
        seed = replica_seed(rep, master_seed)
        rng = np.random.default_rng(seed)
        rep_anchors = []
        for _ in range(key_len):
            blk = (pool_bright[rng.integers(len(pool_bright))] if rng.integers(2)
                   else pool_dark[rng.integers(len(pool_dark))])
            rep_anchors.append((blk["r"], blk["c"]))
        P_anchors_all.append(rep_anchors)

    W_key = []
    for k in range(key_len):
        votes = [
            1 if dct_LL3[P_anchors_all[rep][k][0]:P_anchors_all[rep][k][0] + block_size,
                         P_anchors_all[rep][k][1]:P_anchors_all[rep][k][1] + block_size][0, 0]
                 > global_median else 0
            for rep in range(n_replicas)
        ]
        W_key.append(1 if sum(votes) > n_replicas / 2 else 0)

    return np.array(W_key, dtype=np.uint8), P_anchors_all, bg, LL3, dct_LL3


def extract_key_v3(suspect_bgr, M_buffer_orig, P_anchors_all, W_key_stored,
                    original_shape, block_size=config.BLOCK_SIZE, n_replicas=config.N_REPLICAS):
    """Recompute the fingerprint from a suspect image, remapping registered
    anchor coordinates to the suspect's resolution if it's been resized.

    KNOWN LIMITATION (carried over from the original design, not yet fixed
    here): the remap uses `orig_h // 8` as an approximation of the registered
    LL3 shape rather than the exact stored value, which can drift for resize
    ratios that aren't clean powers of two. See README "Known issues".
    """
    key_len = len(W_key_stored)
    orig_h, orig_w = original_shape[:2]
    susp_h, susp_w = suspect_bgr.shape[:2]
    mask_scaled = (cv2.resize(M_buffer_orig.astype(np.uint8), (susp_w, susp_h),
                               interpolation=cv2.INTER_NEAREST)
                   if (susp_h, susp_w) != (orig_h, orig_w) else M_buffer_orig)
    _, LL3_s, dct_LL3_s = phase2_frequency_topology(suspect_bgr, mask_scaled, block_size)
    scale_r = LL3_s.shape[0] / (orig_h // 8)
    scale_c = LL3_s.shape[1] / (orig_w // 8)

    def remap(coord):
        return (max(0, int(coord[0] * scale_r)), max(0, int(coord[1] * scale_c)))

    h_s, w_s = dct_LL3_s.shape
    anchor_dcs = [
        dct_LL3_s[remap(P_anchors_all[rep][k])[0]:remap(P_anchors_all[rep][k])[0] + block_size,
                   remap(P_anchors_all[rep][k])[1]:remap(P_anchors_all[rep][k])[1] + block_size][0, 0]
        for rep in range(n_replicas) for k in range(key_len)
        if remap(P_anchors_all[rep][k])[0] + block_size <= h_s
        and remap(P_anchors_all[rep][k])[1] + block_size <= w_s
    ]
    suspect_median = np.median(anchor_dcs) if anchor_dcs else 0

    logical_bits = []
    for k in range(key_len):
        votes = []
        for rep in range(n_replicas):
            a = remap(P_anchors_all[rep][k])
            if a[0] + block_size > h_s or a[1] + block_size > w_s:
                continue
            dc = dct_LL3_s[a[0]:a[0] + block_size, a[1]:a[1] + block_size][0, 0]
            votes.append(1 if dc > suspect_median else 0)
        logical_bits.append(1 if votes and sum(votes) > len(votes) / 2 else 0)

    return np.array(logical_bits[:key_len], dtype=np.uint8)


def compute_nc(key_orig, key_extracted) -> float:
    """Normalized correlation, bits mapped to {-1, +1} so an all-zero or
    all-one key doesn't trivially maximize similarity."""
    a = np.where(key_orig == 1, 1.0, -1.0)
    b = np.where(key_extracted == 1, 1.0, -1.0)
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))


def verify_ownership(W_key_stored, key_extracted, threshold=config.NC_THRESHOLD):
    nc = compute_nc(W_key_stored, key_extracted)
    acc = float(np.mean(W_key_stored == key_extracted)) * 100
    return nc, acc, ("OWNERSHIP PROVEN" if nc >= threshold else "NOT PROVEN")


# ── Perceptual hash (near-duplicate detection for blacklist/ledger) ─────────
def get_phash(img_bgr):
    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    return imagehash.phash(PILImage.fromarray(img_rgb))


def phash_distance(img_bgr_a, img_bgr_b) -> int:
    return get_phash(img_bgr_a) - get_phash(img_bgr_b)
```
