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
