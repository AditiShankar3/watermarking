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
google_drive_backup.py
ipfs_storage.py
mongo_sync.py
```

# Files

## File: __init__.py
```python

```

## File: google_drive_backup.py
```python
"""
google_drive_backup.py — pushes the JSON ledger/blacklist/log files to a
Google Drive folder for off-machine backup.

CHANGE from the original notebook: this exact logic was duplicated across
four separate cells (13/17 and two more) with a hardcoded personal path
(/Users/.../Desktop/...) and a hardcoded Drive folder id in each copy. It's
one function here, and every path/id comes from config (i.e. from your
.env file) — see .env.example.
"""
import os
import pickle
import zipfile

import config

BACKUP_FILES = [
    "registration_ledger.zip",
    "tamper_blacklist.json",
    "tamper_log.json",
    "delivery_log.json",
    "gateway_results.json",
    "forensic_audit_log.json",
]

SCOPES = ["https://www.googleapis.com/auth/drive"]


def _zip_ledger() -> str:
    """Compress the ledger before upload (this is the file-size hygiene fix
    discussed earlier: the ledger's m_buffer/master_key arrays compress
    very well, easily 10x, since they're mostly repeated binary values)."""
    zip_path = os.path.join(config.DATA_DIR, "registration_ledger.zip")
    if not os.path.exists(config.LEDGER_FILE):
        return zip_path
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.write(config.LEDGER_FILE, arcname="registration_ledger.json")
    orig_kb = os.path.getsize(config.LEDGER_FILE) / 1024
    zip_kb = os.path.getsize(zip_path) / 1024
    print(f"   Ledger compressed: {orig_kb:.1f} KB -> {zip_kb:.1f} KB "
          f"({100 * (1 - zip_kb / orig_kb):.0f}% smaller)" if orig_kb else "")
    return zip_path


def _authenticate():
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    creds = None
    if os.path.exists(config.GOOGLE_TOKEN_FILE):
        with open(config.GOOGLE_TOKEN_FILE, "rb") as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(config.GOOGLE_CREDENTIALS_FILE):
                raise FileNotFoundError(
                    f"Google OAuth client secret not found at {config.GOOGLE_CREDENTIALS_FILE} "
                    f"(set GOOGLE_CREDENTIALS_FILE in .env)."
                )
            flow = InstalledAppFlow.from_client_secrets_file(config.GOOGLE_CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(config.GOOGLE_TOKEN_FILE, "wb") as token:
            pickle.dump(creds, token)
    return build("drive", "v3", credentials=creds)


def backup_to_drive():
    from googleapiclient.http import MediaFileUpload

    if not config.GOOGLE_DRIVE_FOLDER_ID:
        raise ValueError("GOOGLE_DRIVE_FOLDER_ID not set - see .env.example")

    _zip_ledger()
    service = _authenticate()

    print("=" * 60)
    print("  BACKING UP FILES TO GOOGLE DRIVE")
    print("=" * 60)
    uploaded, skipped = 0, 0
    for filename in BACKUP_FILES:
        file_path = os.path.join(config.DATA_DIR, filename)
        print(f"\nProcessing: {filename}")
        if not os.path.exists(file_path):
            print("  not found, skipping")
            skipped += 1
            continue
        mime_type = "application/zip" if filename.endswith(".zip") else "application/json"
        media = MediaFileUpload(file_path, mimetype=mime_type, resumable=True)
        try:
            uploaded_file = service.files().create(
                body={"name": filename, "parents": [config.GOOGLE_DRIVE_FOLDER_ID]},
                media_body=media, fields="id,name,size",
            ).execute()
            print(f"  uploaded: {uploaded_file['name']}")
            uploaded += 1
        except Exception as e:
            print(f"  upload failed: {e}")
            skipped += 1

    print("\n" + "=" * 60)
    print(f"BACKUP SUMMARY  |  uploaded={uploaded}  skipped={skipped}")
    print("=" * 60)
    return uploaded, skipped
```

## File: ipfs_storage.py
```python
"""
ipfs_storage.py — Pinata/IPFS backup of encrypted vault files.

CHANGE from the original notebook: IPFS upload used to run synchronously
inside encrypt_image(), so registration blocked on a network round-trip to
a third party. IPFS is a redundancy/backup layer, not part of the
watermarking algorithm itself, so it doesn't belong in that critical path.
Here it's fire-and-forget: call backup_to_ipfs_async() after registration
completes; it uploads on a background thread and patches the ledger's
ipfs_cid field in place once the upload finishes (or leaves it None on
failure/timeout — registration itself never blocks on this).
"""
import json
import os
import threading

import requests

import config


def upload_to_ipfs(filepath: str) -> str:
    """Synchronous upload. Prefer backup_to_ipfs_async for use during
    registration; call this directly only in scripts/tests."""
    if not config.PINATA_JWT:
        print("⚠️  PINATA_JWT not set - skipping IPFS upload (see .env.example)")
        return None
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {"Authorization": f"Bearer {config.PINATA_JWT}"}
    with open(filepath, "rb") as f:
        response = requests.post(url, files={"file": f}, headers=headers, timeout=60)
    if response.status_code == 200:
        cid = response.json()["IpfsHash"]
        print(f"✅ IPFS CID: {cid}")
        return cid
    print(f"❌ IPFS upload failed: {response.text}")
    return None


def download_from_ipfs(cid: str, dest_path: str) -> str:
    gateway_url = f"https://ipfs.io/ipfs/{cid}"
    response = requests.get(gateway_url, timeout=30)
    if response.status_code == 200:
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        with open(dest_path, "wb") as f:
            f.write(response.content)
        return dest_path
    raise RuntimeError(f"IPFS download failed ({response.status_code}): {response.text}")


def _patch_ledger_cid(img_hash: str, cid: str):
    """Write the CID into the ledger entry once the background upload
    finishes. Re-signs the record so the HMAC still verifies."""
    from watermark.ledger import _sign_record
    if not os.path.exists(config.LEDGER_FILE):
        return
    with open(config.LEDGER_FILE, "r") as f:
        ledger = json.load(f)
    if img_hash not in ledger:
        return
    record = ledger[img_hash]
    record.pop("hmac_sig", None)
    record["ipfs_cid"] = cid
    record["hmac_sig"] = _sign_record(dict(record))
    ledger[img_hash] = record
    with open(config.LEDGER_FILE, "w") as f:
        json.dump(ledger, f, indent=2)


def backup_to_ipfs_async(vault_path: str, img_hash: str):
    """Fire-and-forget: uploads vault_path to IPFS on a daemon thread and
    patches the ledger entry's ipfs_cid when done. Never raises into the
    caller — registration should never fail because IPFS is slow or down."""
    if not config.PINATA_JWT:
        return

    def _worker():
        try:
            cid = upload_to_ipfs(vault_path)
            if cid:
                _patch_ledger_cid(img_hash, cid)
        except Exception as e:
            print(f"⚠️  Background IPFS backup failed for {img_hash[:8]}...: {e}")

    threading.Thread(target=_worker, daemon=True).start()
```

## File: mongo_sync.py
```python
"""
mongo_sync.py — sync local JSON ledger/blacklist/logs to MongoDB Atlas.

CHANGE from the original notebook: MONGO_URI is read from the environment
(config.MONGO_URI, sourced from your .env file) instead of being a literal
string in the code. If you're moving from the notebook version, rotate your
Atlas password before reusing it here — a credential that ever appeared in
plaintext in a notebook that could be shared or committed should be treated
as burned.
"""
import base64
import json
import os

import numpy as np

import config

try:
    import pymongo
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
except ImportError as e:
    raise ImportError("pymongo not installed - `pip install pymongo`") from e


def connect_mongo():
    if not config.MONGO_URI:
        raise ValueError("MONGO_URI not set - see .env.example. Get it from "
                          "Atlas Console -> Connect -> Drivers.")
    client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=10000)
    client.admin.command("ping")
    print(f"✅ Connected to MongoDB Atlas -> database: '{config.MONGO_DB_NAME}'")
    return client[config.MONGO_DB_NAME]


def compress_large_fields(record: dict) -> dict:
    """m_buffer / master_key -> base64; typically ~500KB -> ~2KB per doc."""
    doc = dict(record)
    if isinstance(doc.get("m_buffer"), list):
        arr = np.array(doc["m_buffer"], dtype=np.uint8)
        doc["m_buffer"] = base64.b64encode(arr.tobytes()).decode("ascii")
        doc["m_buffer_dtype"] = "uint8"
    if isinstance(doc.get("master_key"), list):
        arr = np.array(doc["master_key"], dtype=np.uint8)
        doc["master_key"] = base64.b64encode(arr.tobytes()).decode("ascii")
        doc["master_key_dtype"] = "uint8"
    if isinstance(doc.get("anchors"), list):
        doc["anchors"] = json.dumps(doc["anchors"])
    return doc


def decompress_ledger_record(doc: dict) -> dict:
    doc = dict(doc)
    if isinstance(doc.get("m_buffer"), str):
        doc["m_buffer"] = np.frombuffer(base64.b64decode(doc["m_buffer"]), dtype=np.uint8).tolist()
    if isinstance(doc.get("master_key"), str):
        doc["master_key"] = np.frombuffer(base64.b64decode(doc["master_key"]), dtype=np.uint8).tolist()
    if isinstance(doc.get("anchors"), str):
        doc["anchors"] = json.loads(doc["anchors"])
    doc.pop("_id", None)
    doc.pop("m_buffer_dtype", None)
    doc.pop("master_key_dtype", None)
    return doc


def _upsert(col, doc_id, doc):
    result = col.replace_one({"_id": doc_id}, doc, upsert=True)
    if result.upserted_id is not None:
        return "inserted"
    return "updated" if result.modified_count > 0 else "skipped"


def upload_ledger(db, filepath=config.LEDGER_FILE):
    if not os.path.exists(filepath):
        return 0, 0, 0
    with open(filepath) as f:
        data = json.load(f)
    col = db["ledger"]
    counts = {"inserted": 0, "updated": 0, "skipped": 0}
    for img_hash, record in data.items():
        doc = compress_large_fields(record)
        doc["_id"] = img_hash
        counts[_upsert(col, img_hash, doc)] += 1
    return counts["inserted"], counts["updated"], counts["skipped"]


def upload_dict_collection(db, filepath, collection_name):
    if not os.path.exists(filepath):
        return 0, 0, 0
    with open(filepath) as f:
        data = json.load(f)
    col = db[collection_name]
    counts = {"inserted": 0, "updated": 0, "skipped": 0}
    for doc_id, record in data.items():
        doc = dict(record)
        doc["_id"] = doc_id
        counts[_upsert(col, doc_id, doc)] += 1
    return counts["inserted"], counts["updated"], counts["skipped"]


def upload_results_list(db, filepath, collection_name):
    if not os.path.exists(filepath):
        return 0, 0, 0
    with open(filepath) as f:
        records = json.load(f)
    col = db[collection_name]
    counts = {"inserted": 0, "updated": 0, "skipped": 0}
    for i, record in enumerate(records):
        ts = record.get("timestamp", "").replace(" ", "_").replace(":", "")
        fn = record.get("filename", f"row{i}")[:20]
        doc_id = f"{ts}_{fn}"
        doc = dict(record)
        doc["_id"] = doc_id
        counts[_upsert(col, doc_id, doc)] += 1
    return counts["inserted"], counts["updated"], counts["skipped"]


def sync_all_to_mongo():
    db = connect_mongo()
    tasks = [
        (config.LEDGER_FILE, "ledger", "ledger"),
        (config.BLACKLIST_FILE, "blacklist", "dict"),
        (config.LOG_FILE, "tamper_log", "dict"),
        (config.DELIVERY_LOG_FILE, "delivery_log", "dict"),
        (config.RESULTS_FILE, "results", "list"),
    ]
    totals = {"inserted": 0, "updated": 0, "skipped": 0}
    for filepath, collection, mode in tasks:
        print(f"  {filepath} -> '{collection}'")
        if mode == "ledger":
            ins, upd, skp = upload_ledger(db, filepath)
        elif mode == "list":
            ins, upd, skp = upload_results_list(db, filepath, collection)
        else:
            ins, upd, skp = upload_dict_collection(db, filepath, collection)
        n_total = db[collection].count_documents({})
        print(f"    inserted={ins} updated={upd} skipped={skp}  |  total in cloud={n_total}")
        totals["inserted"] += ins
        totals["updated"] += upd
        totals["skipped"] += skp
    print(f"\nTOTAL  inserted={totals['inserted']}  updated={totals['updated']}  skipped={totals['skipped']}")
    return totals


def download_ledger_from_mongo():
    """Returns entries in the exact shape watermark.ledger.load_all_ledger_entries()
    produces, so the gateway can run against a Mongo-backed ledger without
    any other code changes."""
    db = connect_mongo()
    docs = list(db["ledger"].find({}))
    required = {"tamper_hash", "m_buffer", "m_buffer_shape", "image_shape",
                "image_filename", "master_key", "anchors", "vault_name"}
    entries, skipped = [], 0
    for doc in docs:
        img_hash = doc.get("_id", "unknown")
        missing = required - set(doc.keys())
        if missing:
            skipped += 1
            continue
        try:
            record = decompress_ledger_record(doc)
            m_buf = np.array(record["m_buffer"], dtype=np.uint8).reshape(record["m_buffer_shape"])
            entries.append({
                "img_hash": str(img_hash), "image_filename": record["image_filename"],
                "image_shape": record["image_shape"], "timestamp": record.get("timestamp", ""),
                "tamper_hash": record["tamper_hash"], "M_buffer": m_buf,
                "W_key": np.array(record["master_key"], dtype=np.uint8),
                "P_anchors_all": record["anchors"], "vault_name": record["vault_name"],
                "image_phash": record.get("image_phash", ""), "ipfs_cid": record.get("ipfs_cid"),
            })
        except Exception:
            skipped += 1
    print(f"✅ Downloaded {len(entries)} ledger record(s) from MongoDB ({skipped} skipped)")
    return entries
```
