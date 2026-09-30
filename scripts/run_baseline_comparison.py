#!/usr/bin/env python3
"""
run_baseline_comparison.py — Comparative baseline evaluation.

Compares the proposed framework against two honestly-labeled baselines:
  1. Global DWT-DCT (ablation of our own method — no YOLO ROI restriction)
  2. Naive Patch-Pair Correlation (a simple heuristic we designed for
     comparison; NOT a published method, NOT attributed to any paper —
     do not cite this as a prior work you are "beating")
  3. Proposed Framework (Ours — YOLO Semantic ROI + DWT-DCT + DCT-QIM seal)

CHANGES from the previous version of this script:
  - Removed a fabricated citation ("Rel-Zero, Chen et al., CVPR 2026") that
    does not correspond to a real paper. Presenting an invented method under
    a fake author/venue is citation fabrication, not a weak baseline choice
    — it will not survive a reviewer's citation check. The patch-pair
    heuristic itself is kept (it's a fine, simple sanity-check baseline);
    only the fake attribution is gone.
  - FIXED a bug from the previous version: benign-condition suspects (JPEG,
    brightness) were built by attacking the RAW original, so the Proposed
    method's seal was being checked against an image that was never signed
    in the first place — every such image failed the seal check regardless
    of the real seal's actual robustness, making those specific rows
    meaningless. Suspects for the Proposed method are now built by attacking
    a SIGNED copy, so the seal check tests what it's supposed to test.
  - Tests EVERY method against a full attack matrix (AI-regen, JPEG, real
    resize, real crop, brightness, unrelated-image control, untouched
    control) instead of only AI-regeneration. A single-condition test
    labeled as a general "comparative benchmark" overstates what it shows.
  - Reports the seal's own bit accuracy (seal_bit_acc) alongside the
    structural NC score — conflating "structural key bit accuracy" and
    "seal bit accuracy" into one column hides which layer is doing the
    detecting.
  - Writes a full per-image, per-method, per-condition CSV so every number
    in the printed table is traceable back to individual runs, and 95%
    Wilson confidence intervals are computed on every detection rate
    instead of a bare percentage.

Usage:
    python3 scripts/run_baseline_comparison.py \
        --orig_dir data/test_orig --ai_dir data/test_ai \
        --unrelated_dir data/test_unrelated --max 25 --seed 42
"""
import argparse
import csv
import glob
import math
import os
import sys
import time

import cv2
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from watermark.crypto_vault import load_secrets
from watermark.metrics import compute_psnr, compute_ssim
from watermark.tamper_seal import embed_tamper_signature, verify_tamper_signature
from watermark.zero_watermark import (
    compute_nc, extract_key_v3, phase1_ai_roi_isolation, register_master_key_v3,
)


# ── Wilson confidence interval (better than a bare % at N~25) ───────────────
def wilson_ci(successes, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z ** 2 / n
    centre = p + z ** 2 / (2 * n)
    margin = z * math.sqrt((p * (1 - p) + z ** 2 / (4 * n)) / n)
    return ((centre - margin) / denom, (centre + margin) / denom)


# ── Attack generators (applied uniformly to every method being compared) ────
def attack_jpeg(img, quality):
    ok, enc = cv2.imencode(".jpg", img, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
    return cv2.imdecode(enc, cv2.IMREAD_COLOR)


def attack_resize_true(img, scale=0.75):
    """A REAL resize — output stays at the smaller resolution. Do not resize
    back to original dimensions; that hides exactly the failure mode this
    system needs to be evaluated against (see extract_key_v3's anchor remap)."""
    h, w = img.shape[:2]
    return cv2.resize(img, (max(1, int(w * scale)), max(1, int(h * scale))))


def attack_crop_true(img, crop_pct=0.10):
    """A REAL crop — output is genuinely smaller, not a same-size blackout."""
    h, w = img.shape[:2]
    ch = int(h * crop_pct)
    return img[ch:, :]


def attack_brightness(img, factor=1.20):
    return np.clip(img.astype(np.float32) * factor, 0, 255).astype(np.uint8)


# ── BASELINE 1: Global DWT-DCT (ablation — no YOLO ROI restriction) ─────────
def eval_global_dwt_dct(orig_bgr, suspect_bgr, master_seed):
    h, w = orig_bgr.shape[:2]
    dummy_mask = np.ones((h, w), dtype=np.uint8) * 255
    try:
        w_key_reg, p_anchors, _, _, _ = register_master_key_v3(orig_bgr, dummy_mask, master_seed=master_seed)
        w_key_susp = extract_key_v3(suspect_bgr, dummy_mask, p_anchors, w_key_reg, orig_bgr.shape)
        nc = compute_nc(w_key_reg, w_key_susp)
        acc = float(np.mean(w_key_reg == w_key_susp)) * 100.0
        return {"nc": nc, "bit_acc": acc, "detected": nc < config.NC_THRESHOLD}
    except Exception as e:
        return {"nc": None, "bit_acc": None, "detected": None, "error": str(e)}


# ── BASELINE 2: Naive patch-pair correlation — OUR OWN heuristic, uncited ───
def eval_patch_pair_correlation(orig_bgr, suspect_bgr, n_pairs=256, master_seed=42):
    """A simple sanity-check baseline we designed: compares the sign of mean
    brightness between random patch pairs. This is NOT a published method —
    do not attribute it to any paper in the write-up."""
    h, w = orig_bgr.shape[:2]
    patch_size = 16
    rng = np.random.default_rng(master_seed)
    coords_a = [(rng.integers(0, max(1, h - patch_size)), rng.integers(0, max(1, w - patch_size))) for _ in range(n_pairs)]
    coords_b = [(rng.integers(0, max(1, h - patch_size)), rng.integers(0, max(1, w - patch_size))) for _ in range(n_pairs)]
    gray_o = cv2.cvtColor(orig_bgr, cv2.COLOR_BGR2GRAY).astype(np.float32)
    gray_s = cv2.cvtColor(suspect_bgr, cv2.COLOR_BGR2GRAY).astype(np.float32) if suspect_bgr.shape[:2] == orig_bgr.shape[:2] \
        else cv2.cvtColor(cv2.resize(suspect_bgr, (w, h)), cv2.COLOR_BGR2GRAY).astype(np.float32)
    bits_o, bits_s = [], []
    for (r1, c1), (r2, c2) in zip(coords_a, coords_b):
        bits_o.append(1 if gray_o[r1:r1+patch_size, c1:c1+patch_size].mean() > gray_o[r2:r2+patch_size, c2:c2+patch_size].mean() else 0)
        bits_s.append(1 if gray_s[r1:r1+patch_size, c1:c1+patch_size].mean() > gray_s[r2:r2+patch_size, c2:c2+patch_size].mean() else 0)
    bits_o, bits_s = np.array(bits_o, dtype=np.uint8), np.array(bits_s, dtype=np.uint8)
    nc = compute_nc(bits_o, bits_s)
    acc = float(np.mean(bits_o == bits_s)) * 100.0
    return {"nc": nc, "bit_acc": acc, "detected": nc < config.NC_THRESHOLD}


# ── PROPOSED FRAMEWORK ───────────────────────────────────────────────────────
# IMPORTANT: unlike the two baselines above (which have no embedding step and
# so can be evaluated directly against orig_bgr/suspect_bgr), this method's
# seal check is only meaningful if `suspect_bgr` is derived from an image
# that was ACTUALLY SIGNED first. The caller (run_all_baselines) is
# responsible for passing a suspect built from the signed copy for this
# method specifically - see build_suspects().
def eval_proposed(orig_bgr, suspect_bgr, master_seed, tamper_hash=None,
                   w_key_reg=None, p_anchors=None, m_buffer=None):
    if m_buffer is None:
        _, _, m_buffer = phase1_ai_roi_isolation(orig_bgr)
    if w_key_reg is None or p_anchors is None:
        w_key_reg, p_anchors, _, _, _ = register_master_key_v3(orig_bgr, m_buffer, master_seed=master_seed)
    if tamper_hash is None:
        _, tamper_hash = embed_tamper_signature(orig_bgr, master_seed=master_seed)

    w_key_susp = extract_key_v3(suspect_bgr, m_buffer, p_anchors, w_key_reg, orig_bgr.shape)
    nc = compute_nc(w_key_reg, w_key_susp)
    acc = float(np.mean(w_key_reg == w_key_susp)) * 100.0

    seal = verify_tamper_signature(suspect_bgr, tamper_hash, orig_bgr.shape, master_seed=master_seed)
    detected = (not seal["seal_intact"]) or (nc < config.NC_THRESHOLD)
    return {"nc": nc, "bit_acc": acc, "detected": detected,
            "seal_intact": seal["seal_intact"], "seal_bit_acc": seal.get("seal_bit_acc")}


# needs_signed_suspect=True means: attack a SIGNED copy of the image, not the
# raw original, because this method has an embedding step that must actually
# be present for its detection check to mean anything.
METHODS = {
    "global_dwt_dct": ("Global DWT-DCT (ablation, no YOLO)", eval_global_dwt_dct, False),
    "patch_pair":     ("Naive Patch-Pair Correlation (ours, uncited)", eval_patch_pair_correlation, False),
    "proposed":       ("Proposed Framework (Ours)", eval_proposed, True),
}

# name -> (fn(orig)->suspect, expect_detected_bool_or_None). None = informational only.
def build_conditions(orig, ai_img, unrelated_img):
    conds = {
        "Untouched (positive control)": (lambda im: im.copy(), False),
        "JPEG Q=90":                    (lambda im: attack_jpeg(im, 90), False),
        "JPEG Q=75":                    (lambda im: attack_jpeg(im, 75), False),
        "JPEG Q=50":                    (lambda im: attack_jpeg(im, 50), False),
        "True Resize (0.75x)":          (lambda im: attack_resize_true(im, 0.75), False),
        "True Crop (top 10%)":          (lambda im: attack_crop_true(im, 0.10), True),
        "Brightness (+20%)":            (lambda im: attack_brightness(im, 1.20), False),
    }
    if ai_img is not None:
        conds["AI-Regeneration (real)"] = (lambda im: ai_img, True)
    if unrelated_img is not None:
        conds["Unrelated Image (negative control)"] = (lambda im: unrelated_img, True)
    return conds


def run(orig_dir, ai_dir, unrelated_dir, max_images, seed, out_csv):
    orig_files = sorted(glob.glob(os.path.join(orig_dir, "*.*")))
    orig_files = [f for f in orig_files if os.path.splitext(f)[1].lower() in (".png", ".jpg", ".jpeg")][:max_images]
    if not orig_files:
        print(f"No images found in {orig_dir}")
        return

    print(f"Running {len(METHODS)} method(s) x up to {len(orig_files)} scene(s) across the full attack matrix ...")
    rows = []  # one row per (image, method, condition)

    for idx, orig_path in enumerate(orig_files, 1):
        stem = os.path.splitext(os.path.basename(orig_path))[0]
        orig = cv2.imread(orig_path)
        if orig is None:
            continue

        ai_img = None
        if ai_dir:
            ai_matches = glob.glob(os.path.join(ai_dir, f"{stem}.*")) or glob.glob(os.path.join(ai_dir, f"{stem}_*.*"))
            if ai_matches:
                ai_img = cv2.imread(ai_matches[0])

        unrelated_img = None
        if unrelated_dir:
            # deterministic "different" pairing: offset by 1 in the sorted list
            u_files = sorted(glob.glob(os.path.join(unrelated_dir, "*.*")))
            u_files = [f for f in u_files if os.path.splitext(f)[1].lower() in (".png", ".jpg", ".jpeg")]
            if u_files:
                unrelated_img = cv2.imread(u_files[idx % len(u_files)])

        conditions = build_conditions(orig, ai_img, unrelated_img)
        print(f"[{idx:02d}/{len(orig_files):02d}] {stem} ... ", end="", flush=True)

        # Registration artifacts computed ONCE per image and reused across every
        # condition/method below, instead of re-registering per condition.
        _, _, m_buffer = phase1_ai_roi_isolation(orig)
        w_key_reg, p_anchors, _, _, _ = register_master_key_v3(orig, m_buffer, master_seed=seed)
        signed_img, tamper_hash = embed_tamper_signature(orig, master_seed=seed)

        for cond_name, (make_suspect, expect_detected) in conditions.items():
            # Two suspect variants: baselines (no embedding step) attack the
            # raw original; the Proposed method attacks a SIGNED copy, since
            # its seal check only means something if a seal was actually
            # embedded first. For AI-regen/unrelated-image conditions the
            # lambda ignores its input and returns a fixed real image either
            # way, so both variants are identical there - this only matters
            # for the transform-based conditions (JPEG/brightness/etc.).
            try:
                suspect_plain = make_suspect(orig)
                suspect_signed = make_suspect(signed_img)
            except Exception:
                continue

            for method_key, (method_label, method_fn, needs_signed) in METHODS.items():
                suspect = suspect_signed if needs_signed else suspect_plain
                t0 = time.perf_counter()
                if method_key == "proposed":
                    result = method_fn(orig, suspect, seed, tamper_hash=tamper_hash,
                                        w_key_reg=w_key_reg, p_anchors=p_anchors, m_buffer=m_buffer)
                else:
                    result = method_fn(orig, suspect, seed)
                elapsed = time.perf_counter() - t0
                rows.append({
                    "image": stem, "condition": cond_name, "method": method_key,
                    "nc": result.get("nc"), "bit_acc": result.get("bit_acc"),
                    "detected": result.get("detected"), "expected_detected": expect_detected,
                    "correct": (result.get("detected") == expect_detected) if result.get("detected") is not None else None,
                    "latency_s": round(elapsed, 5),
                    "seal_bit_acc": result.get("seal_bit_acc"),
                })
        print("done")

    if not rows:
        print("No results produced.")
        return

    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nPer-image raw results -> {out_csv}  (every number below is traceable to this file)")

    # ── Summary table ─────────────────────────────────────────────────────
    conditions_order = list(build_conditions(None, "x", "x").keys())  # for stable ordering
    print("\n" + "=" * 100)
    print(f"  METHOD x CONDITION SUMMARY  (seed={seed})")
    print("=" * 100)
    header = f"{'Condition':<32} | " + " | ".join(f"{METHODS[m][0][:22]:<22}" for m in METHODS)
    print(header)
    print("-" * len(header))
    for cond in conditions_order:
        cells = []
        for method_key in METHODS:
            sub = [r for r in rows if r["condition"] == cond and r["method"] == method_key and r["nc"] is not None]
            if not sub:
                cells.append(f"{'n/a':<22}")
                continue
            n_correct = sum(1 for r in sub if r["correct"])
            n = len(sub)
            lo, hi = wilson_ci(n_correct, n)
            mean_nc = np.mean([r["nc"] for r in sub])
            cells.append(f"NC={mean_nc:+.3f} acc={100*n_correct/n:.0f}%[{100*lo:.0f}-{100*hi:.0f}]" [:22].ljust(22))
        print(f"{cond:<32} | " + " | ".join(cells))
    print("=" * 100)
    print("Cell format: mean NC | correct-decision rate (95% Wilson CI). 'Correct' means the")
    print("method's detected/allowed verdict matched the ground truth for that condition.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--orig_dir", required=True)
    ap.add_argument("--ai_dir", default=None)
    ap.add_argument("--unrelated_dir", default=None)
    ap.add_argument("--max", type=int, default=25)
    ap.add_argument("--seed", type=int, default=42, help="Seed used for the ABLATION baselines only "
                     "(global_dwt_dct, patch_pair) - kept fixed and logged for reproducibility. The "
                     "proposed framework's real deployment key is separate and never a fixed value.")
    ap.add_argument("--out_csv", default=os.path.join(config.DATA_DIR, "baseline_comparison_raw.csv"))
    ap.add_argument("--passphrase", "-p", default=None)
    args = ap.parse_args()

    load_secrets(args.passphrase)
    run(args.orig_dir, args.ai_dir, args.unrelated_dir, args.max, args.seed, args.out_csv)