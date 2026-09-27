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
