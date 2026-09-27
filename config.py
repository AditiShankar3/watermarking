"""
config.py — all tunable constants + environment-loaded configuration.

Nothing secret lives in this file. Anything sensitive (Mongo URI, Pinata JWT,
Google Drive folder id, local project paths) is read from environment
variables — see .env.example for the full list you need to set in a local
.env file (never commit .env itself; it's already in .gitignore).
"""
import os
from dotenv import load_dotenv

load_dotenv()  # loads .env if present; real env vars always take precedence

# ── Zero-watermark / tamper-seal parameters ──────────────────────────────────
KEY_LEN        = 256
BLOCK_SIZE     = 4
POOL_PCT       = 0.15
N_REPLICAS     = 5
NC_THRESHOLD   = 0.75
TAMPER_BLOCKS  = 16
MAD_ABS_FLOOR  = 5.0       # absolute MAD floor to avoid false positives
PHASH_MAX_DIST = 10        # pHash Hamming-distance threshold for near-duplicate matching

# ── Filesystem layout ─────────────────────────────────────────────────────────
# Everything writable lives under DATA_DIR, so the repo root stays clean and
# .gitignore only needs one entry to keep runtime artifacts out of git.
DATA_DIR         = os.getenv("WATERMARK_DATA_DIR", "data")
OUTPUT_DIR       = os.path.join(DATA_DIR, "outputs")
VAULT_DIR        = os.path.join(DATA_DIR, "image_vault")
DIAGNOSTICS_DIR  = os.path.join(OUTPUT_DIR, "diagnostics")
HEATMAPS_DIR     = os.path.join(OUTPUT_DIR, "heatmaps")
SIGNED_DIR       = os.path.join(OUTPUT_DIR, "signed")
RECOVERED_DIR    = os.path.join(OUTPUT_DIR, "recovered")

SECRETS_DIR      = os.path.join(DATA_DIR, "secrets")
SEED_FILE        = os.path.join(SECRETS_DIR, "master.seed.enc")
HMAC_SECRET_FILE = os.path.join(SECRETS_DIR, "ledger.hmac_secret.enc")
AES_KEY_FILE     = os.path.join(SECRETS_DIR, "aes.key.enc")

LEDGER_FILE      = os.path.join(DATA_DIR, "registration_ledger.json")
BLACKLIST_FILE   = os.path.join(DATA_DIR, "tamper_blacklist.json")
LOG_FILE         = os.path.join(DATA_DIR, "tamper_log.json")
AUDIT_LOG_FILE   = os.path.join(DATA_DIR, "forensic_audit_log.json")
DELIVERY_LOG_FILE = os.path.join(DATA_DIR, "delivery_log.json")
RESULTS_FILE     = os.path.join(DATA_DIR, "gateway_results.json")

for _d in (DATA_DIR, OUTPUT_DIR, VAULT_DIR, DIAGNOSTICS_DIR,
           HEATMAPS_DIR, SIGNED_DIR, RECOVERED_DIR, SECRETS_DIR):
    os.makedirs(_d, exist_ok=True)

# ── Platform tiers (gateway NC thresholds) ───────────────────────────────────
PLATFORMS = {
    "social_media":  {"name": "SecureShare (Social Media)",
                      "icon": "📱", "nc_threshold": NC_THRESHOLD},
    "news_agency":   {"name": "TruthWire (News Agency)",
                      "icon": "📰", "nc_threshold": 0.80},
    "police_portal": {"name": "CrimeVault (Police Evidence Portal)",
                      "icon": "🚔", "nc_threshold": 0.85},
}

# ── Secrets & third-party config, from environment only ─────────────────────
PINATA_JWT              = os.getenv("PINATA_JWT", "")
MONGO_URI                = os.getenv("MONGO_URI", "")
MONGO_DB_NAME            = os.getenv("MONGO_DB_NAME", "watermark")
GOOGLE_DRIVE_FOLDER_ID   = os.getenv("GOOGLE_DRIVE_FOLDER_ID", "")
GOOGLE_CREDENTIALS_FILE  = os.getenv("GOOGLE_CREDENTIALS_FILE", os.path.join(DATA_DIR, "credentials.json"))
GOOGLE_TOKEN_FILE        = os.getenv("GOOGLE_TOKEN_FILE", os.path.join(SECRETS_DIR, "token.pickle"))

YOLO_DEVICE              = os.getenv("YOLO_DEVICE", "cpu")   # "cpu" or "cuda:0" — set explicitly for reproducible profiling
