"""
pipeline_core.py
─────────────────────────────────────────────────────────────────────────────
This is your "watermark_final_version_14.ipynb" pipeline (Cells 1, 1C, 3, 4,
4B, 4C, 5, 5B, 7, 8) extracted into a plain importable module so a real
backend (api.py) can call it directly instead of the UI simulating fake
results.

WHAT CHANGED vs. the notebook (and ONLY this):
  1. Secrets (seed / HMAC secret / AES key) are no longer entered via an
     interactive getpass() prompt — a server can't block on stdin. They are
     now derived from the WATERMARK_PASSPHRASE environment variable. First
     run creates the encrypted files; later runs decrypt with the same env
     var. Same PBKDF2 + AES-GCM scheme as before — nothing about the crypto
     changed, just where the passphrase comes from.
  2. PINATA_JWT is read from the environment instead of being hardcoded in
     the cell.
  3. upload_image()'s ipywidgets file picker is replaced by passing a
     decoded image array straight in (the API layer handles the HTTP upload).
  4. run_registration() / run_gateway() are each split into a *_core()
     function that takes the image directly, does not call input() or
     print() for control flow, and RETURNS a structured dict instead of
     printing a report. The recovery step (which used to block on
     `input("Recover and deliver original? [y/N]: ")`) is now a separate
     `recover_case()` call the frontend triggers explicitly via a button.
  5. BUG FIX: the original _result_record written to gateway_results.json
     never included which registered image the suspect matched against,
     even though `best_entry` was known. Added "matched_to" and
     "matched_registered_at". This is why the UI could never show a real
     "Matched to" value — the field didn't exist in the data.

Everything else — YOLO ROI masking, DWT/DCT key generation, scattered LSB
tamper seal, MAD localisation, attack-type heuristics, HMAC ledger, dual-hash
blacklist, AES-256-GCM vault, forensic audit log — is your original logic,
unchanged.
"""

import cv2
import numpy as np
import pywt
import hashlib
import hmac as hmac_lib
import secrets
import json
import os
import stat
import struct
import time
import uuid
import warnings
import requests
import matplotlib
matplotlib.use("Agg")  # headless — this process never has a notebook display
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import imagehash
from PIL import Image as PILImage
from ultralytics import YOLO
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as crypto_hashes
from skimage.metrics import structural_similarity as _ssim

warnings.filterwarnings("ignore")

# ── System constants (identical to Cell 1) ────────────────────────────────
KEY_LEN        = 256
BLOCK_SIZE     = 4
POOL_PCT       = 0.15
N_REPLICAS     = 5
NC_THRESHOLD   = 0.75
TAMPER_BLOCKS  = 16
MAD_ABS_FLOOR  = 5.0
PHASH_MAX_DIST = 10
OUTPUT_DIR     = os.environ.get("WATERMARK_OUTPUT_DIR", ".")
VAULT_DIR      = os.path.join(OUTPUT_DIR, "image_vault")
HEATMAP_DIR    = os.path.join(OUTPUT_DIR, "heatmaps")

SEED_FILE        = os.path.join(OUTPUT_DIR, "master.seed.enc")
HMAC_SECRET_FILE = os.path.join(OUTPUT_DIR, "ledger.hmac_secret.enc")
AES_KEY_FILE      = os.path.join(OUTPUT_DIR, "aes.key.enc")
LEDGER_FILE       = os.path.join(OUTPUT_DIR, "registration_ledger.json")
BLACKLIST_FILE    = os.path.join(OUTPUT_DIR, "tamper_blacklist.json")
LOG_FILE          = os.path.join(OUTPUT_DIR, "tamper_log.json")
AUDIT_LOG_FILE    = os.path.join(OUTPUT_DIR, "forensic_audit_log.json")
DELIVERY_LOG_FILE = os.path.join(OUTPUT_DIR, "delivery_log.json")
RESULTS_FILE      = os.path.join(OUTPUT_DIR, "gateway_results.json")

os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(HEATMAP_DIR, exist_ok=True)

PINATA_JWT = os.environ.get("PINATA_JWT", "")

PLATFORMS = {
    "social_media":  {"name": "SecureShare (Social Media)",
                       "icon": "📱", "nc_threshold": NC_THRESHOLD},
    "news_agency":   {"name": "TruthWire (News Agency)",
                       "icon": "📰", "nc_threshold": 0.80},
    "police_portal": {"name": "CrimeVault (Police Evidence Portal)",
                       "icon": "🚔", "nc_threshold": 0.85},
}

# ── FIX 5 secrets, now sourced from env instead of getpass() ──────────────
def _derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=crypto_hashes.SHA256(), length=32,
                      salt=salt, iterations=200_000)
    return kdf.derive(passphrase.encode("utf-8"))

def _encrypt_secret_file(data: bytes, passphrase: str, filepath: str):
    salt = secrets.token_bytes(16)
    key = _derive_key_from_passphrase(passphrase, salt)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    with open(filepath, "wb") as f:
        f.write(salt + nonce + ct)
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

def _load_or_create_secrets():
    passphrase = os.environ.get("WATERMARK_PASSPHRASE")
    if not passphrase:
        raise RuntimeError(
            "WATERMARK_PASSPHRASE environment variable is not set. "
            "This replaces the interactive passphrase prompt from the "
            "notebook — a server process can't block on stdin. Set it "
            "before starting the API (see .env.example)."
        )
    first_run = not os.path.exists(SEED_FILE)
    if first_run:
        seed = secrets.randbelow(2 ** 64)
        hmac_secret = secrets.token_bytes(32)
        aes_key = secrets.token_bytes(32)
        _encrypt_secret_file(struct.pack("<Q", seed), passphrase, SEED_FILE)
        _encrypt_secret_file(hmac_secret, passphrase, HMAC_SECRET_FILE)
        _encrypt_secret_file(aes_key, passphrase, AES_KEY_FILE)
    else:
        try:
            seed = struct.unpack("<Q", _decrypt_secret_file(SEED_FILE, passphrase))[0]
            hmac_secret = _decrypt_secret_file(HMAC_SECRET_FILE, passphrase)
            aes_key = _decrypt_secret_file(AES_KEY_FILE, passphrase)
        except Exception:
            raise ValueError("Wrong WATERMARK_PASSPHRASE or corrupted secret files.")
    return seed, hmac_secret, aes_key

MASTER_SEED, HMAC_SECRET, AES_KEY = _load_or_create_secrets()

def _replica_seed(master_seed, replica_idx):
    raw = f"{master_seed}:replica:{replica_idx}".encode()
    return int(hashlib.sha256(raw).hexdigest(), 16) % (2 ** 31)

def get_phash(img_bgr):
    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    pil_img = PILImage.fromarray(img_rgb)
    return imagehash.phash(pil_img)

def phash_distance(img_bgr_a, img_bgr_b):
    return get_phash(img_bgr_a) - get_phash(img_bgr_b)

# ── Pinata / IPFS (Cell 1C, unchanged logic) ───────────────────────────────
def upload_to_ipfs(filepath: str):
    if not PINATA_JWT:
        print("⚠️  PINATA_JWT not set — skipping IPFS upload, vault stays local-only.")
        return None
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {"Authorization": f"Bearer {PINATA_JWT}"}
    with open(filepath, "rb") as file:
        response = requests.post(url, files={"file": file}, headers=headers, timeout=60)
    if response.status_code == 200:
        return response.json()["IpfsHash"]
    print(f"❌ IPFS Upload Failed: {response.text}")
    return None

def download_from_ipfs(cid: str, dest_path: str):
    gateway_url = f"https://ipfs.io/ipfs/{cid}"
    response = requests.get(gateway_url, timeout=60)
    if response.status_code == 200:
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        with open(dest_path, "wb") as file:
            file.write(response.content)
        return dest_path
    return None

# ── YOLO ROI masking (Cell 3, unchanged) ───────────────────────────────────
_YOLO_MODEL = None
def _get_yolo():
    global _YOLO_MODEL
    if _YOLO_MODEL is None:
        _YOLO_MODEL = YOLO("yolov8n-seg.pt", verbose=False)
    return _YOLO_MODEL

def phase1_ai_roi_isolation(img_bgr, buffer_iterations=3):
    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    h, w = img_bgr.shape[:2]
    model = _get_yolo()
    results = model(img_bgr)
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

def phase2_frequency_topology(img_bgr, M_buffer, block_size=BLOCK_SIZE):
    clean = robust_prefilter_v2(img_bgr)
    gray = cv2.cvtColor(clean, cv2.COLOR_BGR2GRAY).astype(np.float64)
    bg = np.where(M_buffer == 255, gray, 0.0)
    LL1 = pywt.dwt2(bg, "haar")[0]
    LL2 = pywt.dwt2(LL1, "haar")[0]
    LL3 = pywt.dwt2(LL2, "haar")[0]
    return bg, LL3, _dct_blockwise(LL3, bs=block_size)

def phase3_collect_safe_blocks(dct_LL3, M_buffer, block_size=BLOCK_SIZE):
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

def register_master_key_v3(original_bgr, M_buffer, key_len=KEY_LEN, block_size=BLOCK_SIZE,
                            master_seed=None, n_replicas=N_REPLICAS, pool_pct=POOL_PCT):
    if master_seed is None:
        master_seed = MASTER_SEED
    bg, LL3, dct_LL3 = phase2_frequency_topology(original_bgr, M_buffer, block_size)
    safe_blocks = phase3_collect_safe_blocks(dct_LL3, M_buffer, block_size)
    if len(safe_blocks) < key_len:
        raise ValueError("Too few safe background blocks.")
    dc_values = [b["dc"] for b in safe_blocks]
    global_median = np.median(dc_values)
    safe_blocks.sort(key=lambda b: b["dc"])
    pool_n = max(int(len(safe_blocks) * pool_pct), 1)
    pool_dark = safe_blocks[:pool_n]
    pool_bright = safe_blocks[-pool_n:]
    P_anchors_all = []
    for rep in range(n_replicas):
        seed = _replica_seed(master_seed, rep)
        rng = np.random.default_rng(seed)
        rep_anchors = []
        for _ in range(key_len):
            blk = pool_bright[rng.integers(len(pool_bright))] if rng.integers(2) else pool_dark[rng.integers(len(pool_dark))]
            rep_anchors.append((blk["r"], blk["c"]))
        P_anchors_all.append(rep_anchors)
    W_key = []
    for k in range(key_len):
        votes = [1 if dct_LL3[P_anchors_all[rep][k][0]:P_anchors_all[rep][k][0] + block_size,
                              P_anchors_all[rep][k][1]:P_anchors_all[rep][k][1] + block_size][0, 0] > global_median else 0
                 for rep in range(n_replicas)]
        W_key.append(1 if sum(votes) > n_replicas / 2 else 0)
    return np.array(W_key, dtype=np.uint8), P_anchors_all, bg, LL3, dct_LL3

def extract_key_v3(suspect_bgr, M_buffer_orig, P_anchors_all, W_key_stored, original_shape,
                    block_size=BLOCK_SIZE, n_replicas=N_REPLICAS):
    key_len = len(W_key_stored)
    orig_h, orig_w = original_shape[:2]
    susp_h, susp_w = suspect_bgr.shape[:2]
    mask_scaled = cv2.resize(M_buffer_orig.astype(np.uint8), (susp_w, susp_h),
                              interpolation=cv2.INTER_NEAREST) if (susp_h, susp_w) != (orig_h, orig_w) else M_buffer_orig
    _, LL3_s, dct_LL3_s = phase2_frequency_topology(suspect_bgr, mask_scaled, block_size)
    scale_r = LL3_s.shape[0] / (orig_h // 8)
    scale_c = LL3_s.shape[1] / (orig_w // 8)

    def remap(coord):
        return (max(0, int(coord[0] * scale_r)), max(0, int(coord[1] * scale_c)))

    h_s, w_s = dct_LL3_s.shape
    anchor_dcs = [dct_LL3_s[remap(P_anchors_all[rep][k])[0]:remap(P_anchors_all[rep][k])[0] + block_size,
                             remap(P_anchors_all[rep][k])[1]:remap(P_anchors_all[rep][k])[1] + block_size][0, 0]
                  for rep in range(n_replicas) for k in range(key_len)
                  if remap(P_anchors_all[rep][k])[0] + block_size <= h_s
                  and remap(P_anchors_all[rep][k])[1] + block_size <= w_s]
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

def compute_nc(key_orig, key_extracted):
    a = np.where(key_orig == 1, 1.0, -1.0)
    b = np.where(key_extracted == 1, 1.0, -1.0)
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))

def verify_ownership(W_key_stored, key_extracted, threshold=NC_THRESHOLD):
    nc = compute_nc(W_key_stored, key_extracted)
    acc = float(np.mean(W_key_stored == key_extracted)) * 100
    return nc, acc, ("✅ OWNERSHIP PROVEN" if nc >= threshold else "❌ NOT PROVEN")

# ── Scattered LSB tamper seal (Cell 4, unchanged) ──────────────────────────
def _get_lsb_positions(img_bgr, n_bits, master_seed=None):
    if master_seed is None:
        master_seed = MASTER_SEED
    h, w = img_bgr.shape[:2]
    total_px = h * w
    rng = np.random.default_rng(
        int(hashlib.sha256(f"lsb_positions:{master_seed}".encode()).hexdigest(), 16) % (2 ** 31))
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
    return "".join(format((bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3], "x")
                   for i in range(0, len(bits), 4))

def embed_tamper_signature(img_bgr, master_seed=None):
    h = hashlib.sha256(img_bgr.tobytes()).hexdigest()
    signed = _embed_lsb(img_bgr, _hash_to_bits(h), master_seed)
    return signed, h

def verify_tamper_signature(suspect_bgr, registered_hash, original_shape, master_seed=None):
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
            status, detail = "✅ UNTAMPERED (resized copy)", f"Resolution changed ({susp_w}×{susp_h} vs {orig_w}×{orig_h}) but LSB seal intact."
        else:
            status, detail = "❌ TAMPERED — seal destroyed (resized)", "Resolution changed AND seal overwritten. Likely re-encoded after editing."
        return {"status": status, "detail": detail, "content_intact": False, "seal_intact": seal_intact, "resized": True}
    if content_intact:
        status, detail = "✅ UNTAMPERED", "Pixel content matches registered original exactly."
    elif seal_intact:
        status, detail = "⚠️  TAMPERED — seal survived", "Pixel content modified but LSB seal still readable."
    else:
        status, detail = "❌ TAMPERED — seal destroyed", "Pixel content modified AND LSB seal overwritten. AI regeneration confirmed."
    return {"status": status, "detail": detail, "content_intact": content_intact, "seal_intact": seal_intact, "resized": False}

# ── MAD localisation (Cell 4, unchanged) ───────────────────────────────────
def localise_tamper(original_bgr, suspect_bgr, grid=TAMPER_BLOCKS, threshold_pct=15, abs_floor=MAD_ABS_FLOOR):
    oh, ow = original_bgr.shape[:2]
    susp_r = cv2.resize(suspect_bgr, (ow, oh)) if suspect_bgr.shape[:2] != (oh, ow) else suspect_bgr.copy()
    diff = np.abs(original_bgr.astype(np.float32) - susp_r.astype(np.float32)).mean(axis=2)
    cell_h, cell_w = oh // grid, ow // grid
    mad_grid = np.array([[diff[gr * cell_h:(gr + 1) * cell_h, gc * cell_w:(gc + 1) * cell_w].mean()
                           for gc in range(grid)] for gr in range(grid)], dtype=np.float32)
    pct_cutoff = np.percentile(mad_grid, 100 - threshold_pct)
    tamper_map = (mad_grid >= pct_cutoff) & (mad_grid >= abs_floor)
    return tamper_map, mad_grid, cell_h, cell_w

def show_tamper_localisation(original_bgr, suspect_bgr, tamper_map, mad_grid, cell_h, cell_w, save_path):
    oh, ow = original_bgr.shape[:2]
    orig_rgb = cv2.cvtColor(original_bgr, cv2.COLOR_BGR2RGB)
    susp_r = cv2.resize(suspect_bgr, (ow, oh)) if suspect_bgr.shape[:2] != (oh, ow) else suspect_bgr.copy()
    susp_rgb = cv2.cvtColor(susp_r, cv2.COLOR_BGR2RGB)
    grid = tamper_map.shape[0]
    n_t = int(tamper_map.sum())
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    axes[0].imshow(orig_rgb); axes[0].set_title("Recovered Original", fontsize=13, fontweight="bold"); axes[0].axis("off")
    axes[1].imshow(susp_rgb)
    axes[1].set_title(f"Tampered Suspect — {n_t} flagged region(s)" if n_t > 0 else "Suspect — No significant tampering regions found",
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
    axes[2].set_title(f"MAD heatmap  (floor={MAD_ABS_FLOOR})", fontsize=13, fontweight="bold")
    plt.colorbar(im, ax=axes[2], label="Mean abs pixel diff")
    plt.suptitle("TAMPER LOCALISATION REPORT", fontsize=15, fontweight="bold", color="crimson", y=1.01)
    plt.tight_layout()
    plt.savefig(save_path, bbox_inches="tight", dpi=150)
    plt.close()

# ── AES-256-GCM vault + Pinata (Cell 4, unchanged) ─────────────────────────
def encrypt_image(img_bgr, vault_name, aes_key=None):
    if aes_key is None:
        aes_key = AES_KEY
    ok, buf = cv2.imencode(".png", img_bgr)
    if not ok:
        raise ValueError("Failed to encode image to PNG bytes")
    plaintext = buf.tobytes()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    vault_path = os.path.join(VAULT_DIR, vault_name + ".enc")
    with open(vault_path, "wb") as f:
        f.write(nonce + ciphertext)
    try:
        os.chmod(vault_path, stat.S_IRUSR | stat.S_IWUSR)
    except AttributeError:
        pass
    ipfs_cid = None
    try:
        ipfs_cid = upload_to_ipfs(vault_path)
    except Exception as e:
        print(f"⚠️  IPFS upload failed — evidence stays local-only for now: {e}")
    encrypt_image.last_cid = ipfs_cid
    return vault_name

def decrypt_image(vault_name, aes_key=None, ipfs_cid=None):
    if aes_key is None:
        aes_key = AES_KEY
    vault_path = os.path.join(VAULT_DIR, vault_name + ".enc")
    if not os.path.exists(vault_path) and ipfs_cid:
        download_from_ipfs(ipfs_cid, vault_path)
    with open(vault_path, "rb") as f:
        raw = f.read()
    nonce, ct = raw[:12], raw[12:]
    plaintext = AESGCM(aes_key).decrypt(nonce, ct, None)
    arr = np.frombuffer(plaintext, dtype=np.uint8)
    return cv2.imdecode(arr, cv2.IMREAD_COLOR)

def recover_original(entry, save_path):
    if "vault_name" not in entry:
        return None
    try:
        img = decrypt_image(entry["vault_name"], ipfs_cid=entry.get("ipfs_cid"))
        cv2.imwrite(save_path, img)
        return img
    except Exception as e:
        print(f"   ⚠️  Recovery failed: {e}")
        return None

# ── Attack-type classifier (Cell 4B, unchanged) ────────────────────────────
def classify_attack_type(tamper, tamper_map, mad_grid, best_nc, nc_threshold, second_best_nc=None,
                          psnr_val=None, ssim_val=None, collusion_margin=0.05,
                          ssim_compression_floor=0.90, ssim_ai_ceiling=0.85,
                          psnr_ai_ceiling=28.0, mad_quant_ceiling=12.0, mad_splice_floor=20.0):
    resized = tamper.get("resized", False)
    seal_intact = tamper.get("seal_intact", False)
    if resized and seal_intact:
        return ("None (Benign Transformation)", "Resolution changed but LSB seal intact — legitimate resize, no attack.", "heuristic")
    if (not resized) and tamper.get("content_intact", False):
        return ("None (Untampered)", "Exact pixel match to registered original.", "heuristic")
    if tamper_map is None or mad_grid is None:
        return ("Unclassified Tampering", "Seal broken but tamper-map unavailable for finer classification.", "heuristic")
    total_cells = tamper_map.size
    n_tampered = int(tamper_map.sum())
    tamper_pct = (n_tampered / total_cells) * 100
    flagged_vals = mad_grid[tamper_map] if n_tampered > 0 else np.array([0.0])
    mean_mad_flag = float(flagged_vals.mean())
    if resized and not seal_intact:
        return ("Resize + Re-encoding Attack",
                f"Resolution changed AND seal destroyed — image was resized and/or resaved after editing (resolution {tamper.get('detail', '')}).",
                "heuristic")
    if second_best_nc is not None and (best_nc - second_best_nc) < collusion_margin and best_nc < nc_threshold + 0.10:
        return ("Possible Collusion Attack",
                f"Structural fingerprint sits nearly equidistant between two registered originals (NC {best_nc:.4f} vs {second_best_nc:.4f}, "
                f"margin {best_nc - second_best_nc:.4f}) — consistent with an image blended/averaged from multiple watermarked sources.",
                "heuristic")
    if ssim_val is not None and psnr_val is not None:
        if ssim_val < ssim_ai_ceiling or psnr_val < psnr_ai_ceiling:
            return ("AI Regeneration / Pixel-Laundering Attack",
                    f"Global fidelity collapsed (SSIM={ssim_val:.3f}, PSNR={psnr_val:.2f} dB) relative to the recovered original — "
                    f"broad structural reworking consistent with AI-based regeneration rather than a local edit or recompression.",
                    "heuristic")
        if ssim_val >= ssim_compression_floor and mean_mad_flag < mad_quant_ceiling:
            return ("JPEG Recompression / Quantization Attack",
                    f"Global structure preserved (SSIM={ssim_val:.3f}, PSNR={psnr_val:.2f} dB) and flagged cells show only low-magnitude "
                    f"difference (mean MAD={mean_mad_flag:.1f}, just above the {MAD_ABS_FLOOR} floor) — consistent with lossy recompression.",
                    "heuristic")
    if tamper_pct <= 20 and mean_mad_flag >= mad_splice_floor:
        return ("Localized Splicing / Object Insertion-Removal",
                f"Tampering concentrated in {tamper_pct:.1f}% of the grid with high contrast (mean flagged MAD={mean_mad_flag:.1f}) — "
                f"consistent with a pasted/removed object or region edit.",
                "heuristic")
    return ("Unclassified Tampering",
            f"Seal broken, {tamper_pct:.1f}% of grid flagged (mean flagged MAD={mean_mad_flag:.1f}"
            + (f", SSIM={ssim_val:.3f}, PSNR={psnr_val:.2f} dB" if ssim_val is not None else "")
            + ") — pattern doesn't cleanly match a known category; needs manual review.",
            "heuristic")

# ── Metrics (Cell 4C, unchanged) ───────────────────────────────────────────
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

class PhaseTimer:
    def __init__(self):
        self.times = {}
        self._t0_total = time.time()

    class _Ctx:
        def __init__(self, outer, name):
            self.outer, self.name = outer, name
        def __enter__(self):
            self._t0 = time.time(); return self
        def __exit__(self, *exc):
            self.outer.times[self.name] = round(time.time() - self._t0, 4)

    def phase(self, name):
        return self._Ctx(self, name)

    def summary(self):
        self.times["total"] = round(time.time() - self._t0_total, 4)
        return dict(self.times)

def estimate_complexity(phase_times: dict, n_entries: int, image_shape: tuple):
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
    }

# ── HMAC-signed ledger + dual-hash blacklist (Cell 5, unchanged) ──────────
class LedgerTamperedError(Exception):
    pass

def get_image_hash(img_bgr):
    return hashlib.sha256(img_bgr.tobytes()).hexdigest()

def _sign_record(record):
    payload = json.dumps(record, sort_keys=True).encode()
    return hmac_lib.new(HMAC_SECRET, payload, hashlib.sha256).hexdigest()

def _verify_record(record):
    stored = record.pop("hmac_sig", None)
    if stored is None:
        raise LedgerTamperedError("Missing HMAC signature.")
    expected = _sign_record(dict(record))
    record["hmac_sig"] = stored
    if not hmac_lib.compare_digest(stored, expected):
        raise LedgerTamperedError("HMAC mismatch — record tampered.")

def save_to_ledger(image_filename, img_bgr, M_buffer, W_key, P_anchors_all, tamper_hash, vault_name, ipfs_cid=None):
    img_hash = get_image_hash(img_bgr)
    ph = str(get_phash(img_bgr))
    ledger = {}
    if os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, "r") as f:
            ledger = json.load(f)
    record = {
        "image_filename": image_filename, "image_hash": img_hash, "image_phash": ph,
        "image_shape": list(img_bgr.shape), "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tamper_hash": tamper_hash, "m_buffer": M_buffer.flatten().tolist(),
        "m_buffer_shape": list(M_buffer.shape), "master_key": W_key.tolist(),
        "anchors": P_anchors_all, "vault_name": vault_name, "ipfs_cid": ipfs_cid,
    }
    record["hmac_sig"] = _sign_record(dict(record))
    ledger[img_hash] = record
    with open(LEDGER_FILE, "w") as f:
        json.dump(ledger, f, indent=2)

def load_all_ledger_entries():
    if not os.path.exists(LEDGER_FILE):
        raise FileNotFoundError("Ledger not found — register at least one image first.")
    with open(LEDGER_FILE, "r") as f:
        ledger = json.load(f)
    REQUIRED = {"tamper_hash", "m_buffer", "m_buffer_shape", "image_shape", "image_filename", "master_key", "anchors", "vault_name"}
    entries = []
    for img_hash, record in ledger.items():
        if REQUIRED - set(record.keys()):
            continue
        try:
            _verify_record(record)
        except LedgerTamperedError:
            continue
        m_buf = np.array(record["m_buffer"], dtype=np.uint8).reshape(record["m_buffer_shape"])
        entries.append({
            "img_hash": img_hash, "image_filename": record["image_filename"],
            "image_shape": record["image_shape"], "timestamp": record["timestamp"],
            "tamper_hash": record["tamper_hash"], "M_buffer": m_buf,
            "W_key": np.array(record["master_key"], dtype=np.uint8),
            "P_anchors_all": record["anchors"], "vault_name": record["vault_name"],
            "image_phash": record.get("image_phash", ""), "ipfs_cid": record.get("ipfs_cid"),
        })
    return entries

def add_to_blacklist(img_bgr, filename, reason):
    img_hash = get_image_hash(img_bgr)
    ph = str(get_phash(img_bgr))
    blacklist = {}
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "r") as f:
            blacklist = json.load(f)
    if img_hash not in blacklist:
        record = {"filename": filename, "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   "reason": reason, "img_hash": img_hash, "img_phash": ph}
        record["hmac_sig"] = _sign_record(dict(record))
        blacklist[img_hash] = record
        with open(BLACKLIST_FILE, "w") as f:
            json.dump(blacklist, f, indent=2)

def is_blacklisted(img_bgr):
    if not os.path.exists(BLACKLIST_FILE):
        return False, None, None
    img_hash = get_image_hash(img_bgr)
    with open(BLACKLIST_FILE, "r") as f:
        blacklist = json.load(f)
    if img_hash in blacklist:
        record = blacklist[img_hash]
        try:
            _verify_record(record); return True, record, "exact"
        except LedgerTamperedError:
            pass
    suspect_ph = get_phash(img_bgr)
    for key, record in blacklist.items():
        stored_ph_str = record.get("img_phash", "")
        if not stored_ph_str:
            continue
        try:
            stored_ph = imagehash.hex_to_hash(stored_ph_str)
        except Exception:
            continue
        if (suspect_ph - stored_ph) <= PHASH_MAX_DIST:
            try:
                _verify_record(record); return True, record, "perceptual"
            except LedgerTamperedError:
                continue
    return False, None, None

def write_block_log(filename, img_bgr, block_reasons, nc, tamper_status):
    img_hash = get_image_hash(img_bgr)
    log = {}
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            log = json.load(f)
    key = f"{img_hash[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    log[key] = {"filename": filename, "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "img_hash": img_hash, "nc_score": round(nc, 4), "tamper": tamper_status, "reasons": block_reasons}
    with open(LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)

# ── Forensic audit log (Cell 5B, unchanged) ────────────────────────────────
def _audit_entry_hash(entry_core: dict) -> str:
    return hashlib.sha256(json.dumps(entry_core, sort_keys=True).encode()).hexdigest()

def log_audit_event(event_type, filename=None, img_bgr=None, decision=None, details=None):
    audit_log = []
    if os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, "r") as f:
            audit_log = json.load(f)
    prev_hash = audit_log[-1]["entry_hash"] if audit_log else "0" * 64
    entry_core = {"seq": len(audit_log), "event_type": event_type,
                  "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "filename": filename,
                  "image_hash": get_image_hash(img_bgr) if img_bgr is not None else None,
                  "decision": decision, "details": details or {}, "prev_hash": prev_hash}
    entry_core["entry_hash"] = _audit_entry_hash(entry_core)
    entry = dict(entry_core)
    entry["hmac_sig"] = _sign_record(dict(entry))
    audit_log.append(entry)
    with open(AUDIT_LOG_FILE, "w") as f:
        json.dump(audit_log, f, indent=2)
    return entry

# ── Delivery log + recovery delivery (Cell 8, unchanged) ──────────────────
def _log_delivery(img_bgr, filename):
    img_hash = get_image_hash(img_bgr)
    ph = str(get_phash(img_bgr))
    log = {}
    if os.path.exists(DELIVERY_LOG_FILE):
        with open(DELIVERY_LOG_FILE, "r") as f:
            log = json.load(f)
    record = {"filename": filename, "delivered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
              "img_hash": img_hash, "img_phash": ph, "status": "delivered_original"}
    record["hmac_sig"] = _sign_record(dict(record))
    log[img_hash] = record
    with open(DELIVERY_LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)

def _is_delivered_original(img_bgr):
    if not os.path.exists(DELIVERY_LOG_FILE):
        return False, None
    img_hash = get_image_hash(img_bgr)
    with open(DELIVERY_LOG_FILE, "r") as f:
        log = json.load(f)
    if img_hash in log:
        record = log[img_hash]
        try:
            _verify_record(record); return True, record
        except LedgerTamperedError:
            pass
    return False, None

def _is_tampered_delivery(img_bgr):
    if not os.path.exists(DELIVERY_LOG_FILE):
        return False, None, None
    img_hash = get_image_hash(img_bgr)
    suspect_ph = get_phash(img_bgr)
    with open(DELIVERY_LOG_FILE, "r") as f:
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
        if dist <= PHASH_MAX_DIST:
            try:
                _verify_record(record); return True, record, dist
            except LedgerTamperedError:
                continue
    return False, None, None

def deliver_recovered_original(entry, suspect_filename):
    tmp_path = os.path.join(OUTPUT_DIR, f"_temp_recovered_{uuid.uuid4().hex}.png")
    recovered = recover_original(entry, save_path=tmp_path)
    if recovered is None:
        return None
    delivered_signed, delivery_hash = embed_tamper_signature(recovered)
    base = os.path.splitext(suspect_filename)[0]
    delivery_name = f"recovered_{base}.png"
    delivery_path = os.path.join(OUTPUT_DIR, delivery_name)
    cv2.imwrite(delivery_path, delivered_signed)
    _log_delivery(delivered_signed, delivery_name)
    log_audit_event("RECOVERY_DELIVERED", filename=suspect_filename, img_bgr=delivered_signed,
                     decision="DELIVERED", details={"delivery_name": delivery_name})
    if os.path.exists(tmp_path):
        os.remove(tmp_path)
    return delivery_path

# ── Results file (Cell 8) ──────────────────────────────────────────────────
def _append_result(record: dict):
    results = []
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE, "r") as f:
            try:
                results = json.load(f)
            except Exception:
                results = []
    results.append(record)
    with open(RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=2)

def load_results():
    if not os.path.exists(RESULTS_FILE):
        return []
    with open(RESULTS_FILE, "r") as f:
        try:
            return json.load(f)
        except Exception:
            return []

# ─────────────────────────────────────────────────────────────────────────
# Non-interactive entry points for the API layer
# ─────────────────────────────────────────────────────────────────────────

def register_image(img_bgr, filename):
    """Non-interactive version of Cell 7's run_registration()."""
    flagged, bl_record, match_type = is_blacklisted(img_bgr)
    if flagged:
        log_audit_event("REGISTRATION_REFUSED_BLACKLISTED", filename=filename, img_bgr=img_bgr,
                         decision="REFUSED", details={"match_type": match_type, "reason": bl_record["reason"]})
        return {"ok": False, "reason": "blacklisted", "detail": bl_record["reason"],
                "match_type": match_type, "blocked_at": bl_record["blocked_at"]}

    img_rgb, M_binary, M_buffer = phase1_ai_roi_isolation(img_bgr)
    W_key, P_anchors_all, bg, LL3, dct_LL3 = register_master_key_v3(img_bgr, M_buffer)
    img_signed, tamper_hash = embed_tamper_signature(img_bgr)

    base_name = os.path.splitext(filename)[0]
    vault_name = encrypt_image(img_bgr, vault_name=base_name)

    save_to_ledger(filename, img_bgr, M_buffer, W_key, P_anchors_all, tamper_hash, vault_name,
                    ipfs_cid=getattr(encrypt_image, "last_cid", None))

    signed_name = base_name + "_signed" + (os.path.splitext(filename)[1] or ".png")
    signed_path = os.path.join(OUTPUT_DIR, signed_name)
    cv2.imwrite(signed_path, img_signed)

    log_audit_event("REGISTRATION", filename=filename, img_bgr=img_bgr, decision="REGISTERED",
                     details={"vault_name": vault_name, "tamper_hash": tamper_hash[:16]})

    return {
        "ok": True,
        "filename": filename,
        "signed_name": signed_name,
        "signed_path": signed_path,
        "key_balance_pct": round(float(W_key.mean()) * 100, 1),
        "key_len_bits": KEY_LEN,
        "tamper_hash": tamper_hash,
        "vault_name": vault_name,
        "vault_path": os.path.join(VAULT_DIR, vault_name + ".enc"),
        "ipfs_cid": getattr(encrypt_image, "last_cid", None),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# in-memory store so the "recover & deliver" button can act on a specific
# gateway-check result without re-uploading the suspect image
_CASE_STORE = {}

def gateway_check(img_bgr, filename, platform):
    """Non-interactive version of Cell 8's run_gateway(). Recovery is NOT
    performed here — see recover_case() below, called separately by the UI."""
    if platform not in PLATFORMS:
        raise ValueError(f"Choose from: {list(PLATFORMS.keys())}")
    cfg = PLATFORMS[platform]
    pt = PhaseTimer()
    _t_start = time.time()

    is_clean_delivery, dl_record = _is_delivered_original(img_bgr)
    if is_clean_delivery:
        log_audit_event("ALLOW_DELIVERED_ORIGINAL", filename=filename, img_bgr=img_bgr, decision="ALLOW",
                         details={"platform": platform, "delivered_as": dl_record["filename"]})
        return {"decision": "ALLOW", "filename": filename, "reason": "verified_clean_delivery",
                "matched_to": dl_record["filename"], "matched_registered_at": dl_record["delivered_at"]}

    is_tampered_delivery, td_record, ph_dist = _is_tampered_delivery(img_bgr)
    if is_tampered_delivery:
        add_to_blacklist(img_bgr, filename, "Post-delivery tampering: edited version of delivered original")
        write_block_log(filename, img_bgr, ["Post-delivery tampering"], 0.0, "TAMPERED POST-DELIVERY")
        log_audit_event("BLOCK_POST_DELIVERY_TAMPER", filename=filename, img_bgr=img_bgr, decision="BLOCK",
                         details={"platform": platform, "phash_dist": ph_dist, "original_delivery": td_record["filename"]})
        return {"decision": "BLOCK", "filename": filename, "reason": "post_delivery_tamper",
                "matched_to": td_record["filename"], "attack_type": "Post-Delivery Tampering",
                "attack_detail": f"Edited version of a previously delivered original (pHash dist={ph_dist})."}

    try:
        _check_entries = load_all_ledger_entries()
        _suspect_hash = get_image_hash(img_bgr)
        _orig_match = next((e for e in _check_entries if e["img_hash"] == _suspect_hash), None)
    except Exception:
        _orig_match = None

    if _orig_match is not None:
        result = {
            "filename": filename, "image_shape": list(img_bgr.shape),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "decision": "ALLOW",
            "tamper_status": "INTACT", "seal_intact": True, "content_intact": True,
            "nc_score": 1.0, "bit_accuracy": 100.0, "ber": 0.0, "n_tampered_cells": 0,
            "resized": False, "block_reasons": [], "attack_type": "None (Untampered)",
            "attack_detail": "Exact pixel match to registered original.",
            "matched_to": _orig_match["image_filename"], "matched_registered_at": _orig_match["timestamp"],
            "recovery_attempted": False, "recovery_success": False, "recovery_time_s": None,
            "check_time_s": round(time.time() - _t_start, 3), "can_recover": False,
        }
        _append_result(result)
        log_audit_event("ALLOW_EXACT_MATCH", filename=filename, img_bgr=img_bgr, decision="ALLOW",
                         details={"platform": platform, "registered_as": _orig_match["image_filename"]})
        return result

    flagged, bl_record, match_type = is_blacklisted(img_bgr)
    if flagged:
        result = {
            "filename": filename, "image_shape": list(img_bgr.shape),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "decision": "BLOCK",
            "tamper_status": "BLACKLISTED", "seal_intact": None, "content_intact": None,
            "nc_score": 0.0, "bit_accuracy": 0.0, "ber": 1.0, "n_tampered_cells": 0,
            "resized": False, "block_reasons": ["blacklisted"], "attack_type": "N/A (Pre-blacklisted)",
            "attack_detail": bl_record["reason"], "matched_to": None, "matched_registered_at": None,
            "recovery_attempted": False, "recovery_success": False, "recovery_time_s": None,
            "check_time_s": round(time.time() - _t_start, 3), "can_recover": False,
        }
        _append_result(result)
        log_audit_event("BLOCK_BLACKLISTED", filename=filename, img_bgr=img_bgr, decision="BLOCK",
                         details={"platform": platform, "match_type": match_type, "reason": bl_record["reason"]})
        return result

    entries = load_all_ledger_entries()
    best_nc, best_acc, best_entry = 0.0, 0.0, None
    second_best_nc = 0.0
    with pt.phase("nc_verification"):
        for entry in entries:
            eh, ew = entry["image_shape"][:2]
            img_r = cv2.resize(img_bgr, (ew, eh)) if img_bgr.shape[:2] != (eh, ew) else img_bgr
            key_ext = extract_key_v3(img_r, entry["M_buffer"], entry["P_anchors_all"], entry["W_key"], tuple(entry["image_shape"]))
            nc, acc, _ = verify_ownership(entry["W_key"], key_ext)
            if nc > best_nc:
                second_best_nc = best_nc
                best_nc, best_acc, best_entry = nc, acc, entry
            elif nc > second_best_nc:
                second_best_nc = nc

    if best_entry is None:
        return {"decision": "BLOCK", "filename": filename, "reason": "no_registered_match"}

    eh, ew = best_entry["image_shape"][:2]
    img_r = cv2.resize(img_bgr, (ew, eh)) if img_bgr.shape[:2] != (eh, ew) else img_bgr.copy()

    with pt.phase("tamper_seal_check"):
        tamper = verify_tamper_signature(img_r, best_entry["tamper_hash"], tuple(best_entry["image_shape"]))
        tamper_ok = tamper["seal_intact"]

    n_tampered, heatmap_rel_path, recovered_orig = 0, None, None
    tamper_map, mad_grid = None, None
    if not tamper_ok:
        with pt.phase("localisation"):
            tmp_recover_path = os.path.join(OUTPUT_DIR, f"_temp_recover_{uuid.uuid4().hex}.png")
            recovered_orig = recover_original(best_entry, save_path=tmp_recover_path)
            if recovered_orig is not None:
                tamper_map, mad_grid, cell_h, cell_w = localise_tamper(recovered_orig, img_bgr)
                n_tampered = int(tamper_map.sum())
                heatmap_name = f"{os.path.splitext(filename)[0]}_{uuid.uuid4().hex[:8]}_heatmap.png"
                heatmap_full_path = os.path.join(HEATMAP_DIR, heatmap_name)
                show_tamper_localisation(recovered_orig, img_bgr, tamper_map, mad_grid, cell_h, cell_w, heatmap_full_path)
                heatmap_rel_path = heatmap_name
            if os.path.exists(tmp_recover_path):
                os.remove(tmp_recover_path)

    ownership_ok = best_nc >= cfg["nc_threshold"]
    block_reasons = []
    if not tamper_ok:
        block_reasons.append(f"Tamper seal broken — {tamper['detail']}")
    if not ownership_ok:
        block_reasons.append(f"NC score {best_nc:.4f} below threshold {cfg['nc_threshold']}")
    decision = "BLOCK" if block_reasons else "ALLOW"

    psnr_val, ssim_val = None, None
    if recovered_orig is not None:
        psnr_val = compute_psnr(recovered_orig, img_r)
        ssim_val = compute_ssim(recovered_orig, img_r)

    attack_label, attack_detail, attack_conf = classify_attack_type(
        tamper, tamper_map, mad_grid, best_nc, cfg["nc_threshold"],
        second_best_nc=second_best_nc, psnr_val=psnr_val, ssim_val=ssim_val)

    ber_val = compute_ber_from_accuracy(best_acc)
    phase_times = pt.summary()
    complexity_info = estimate_complexity(phase_times, len(entries), img_bgr.shape)

    if decision == "BLOCK":
        add_to_blacklist(img_r, filename, block_reasons[0] if block_reasons else "Check failed")
        write_block_log(filename, img_r, block_reasons, best_nc, tamper["status"])

    log_audit_event(decision, filename=filename, img_bgr=img_r, decision=decision,
                     details={"platform": platform, "nc_score": round(float(best_nc), 4),
                              "bit_accuracy": round(float(best_acc), 2), "ber": ber_val,
                              "seal_intact": bool(tamper_ok), "block_reasons": block_reasons,
                              "attack_type": attack_label})

    case_id = uuid.uuid4().hex
    can_recover = (decision == "BLOCK")
    if can_recover:
        _CASE_STORE[case_id] = {"best_entry": best_entry, "filename": filename}

    result = {
        "case_id": case_id if can_recover else None,
        "filename": filename,
        "image_shape": list(img_bgr.shape),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "decision": decision,
        "tamper_status": tamper["status"],
        "tamper_detail": tamper["detail"],
        "seal_intact": bool(tamper_ok),
        "content_intact": bool(tamper.get("content_intact")) if tamper.get("content_intact") is not None else None,
        "resized": bool(tamper.get("resized", False)),
        "nc_score": round(float(best_nc), 4),
        "second_best_nc": round(float(second_best_nc), 4),
        "bit_accuracy": round(float(best_acc), 2),
        "ber": ber_val,
        "psnr_db": round(psnr_val, 2) if psnr_val is not None else None,
        "ssim": round(ssim_val, 4) if ssim_val is not None else None,
        "n_tampered_cells": int(n_tampered),
        "total_cells": TAMPER_BLOCKS * TAMPER_BLOCKS,
        "heatmap_file": heatmap_rel_path,
        "block_reasons": block_reasons,
        "attack_type": attack_label,
        "attack_detail": attack_detail,
        # FIX: these two fields never existed in the original _result_record
        "matched_to": best_entry["image_filename"],
        "matched_registered_at": best_entry["timestamp"],
        "phase_times_s": phase_times,
        "computational_complexity": complexity_info,
        "recovery_attempted": False,
        "recovery_success": False,
        "recovery_time_s": None,
        "check_time_s": phase_times.get("total", 0),
        "can_recover": can_recover,
    }
    _append_result(result)
    return result


def recover_case(case_id: str):
    """Called when the user clicks 'Decrypt & deliver original' in the UI —
    replaces the notebook's blocking input() prompt in run_gateway()."""
    case = _CASE_STORE.pop(case_id, None)
    if case is None:
        return {"ok": False, "reason": "unknown_or_expired_case"}
    _t_rec = time.time()
    delivery_path = deliver_recovered_original(case["best_entry"], case["filename"])
    recovery_time_s = round(time.time() - _t_rec, 3)
    if delivery_path is None:
        return {"ok": False, "reason": "vault_decrypt_failed"}
    return {
        "ok": True,
        "delivery_path": delivery_path,
        "delivery_filename": os.path.basename(delivery_path),
        "recovery_time_s": recovery_time_s,
    }
