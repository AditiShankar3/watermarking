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
