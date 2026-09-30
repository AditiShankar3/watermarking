#!/usr/bin/env python3
"""
generate_paper_benchmark_table.py — the single benchmark script to cite in
the paper. Produces two separate, honestly-named tables plus a raw CSV.

DESIGN PRINCIPLES (why this differs from earlier versions):
  - Robustness (ownership retention under BENIGN edits) and detection
    (tamper/rejection rate under MALICIOUS or out-of-system content) are
    reported as separate tables with separate metric names, because they
    are different claims. "TPR" meant two different things in earlier
    versions of this script - that's gone.
  - Every "attack" that claims to test resize/crop is a REAL resize/crop
    (different final dimensions) - not a resize-then-resize-back, which
    silently skips the exact code path (extract_key_v3's anchor remap)
    that most needs testing.
  - Includes an untouched-signed POSITIVE control and an unrelated-image
    NEGATIVE control in every run, not as an afterthought.
  - Reports Wilson 95% confidence intervals on every rate - at N~24-25,
    a bare percentage overstates precision.
  - Writes one row per (image, condition) to CSV so reviewers (or you,
    six months from now) can recompute any number in the paper.
  - Uses the vault's REAL loaded master seed (via crypto_vault), not a
    hardcoded value, so results reflect actual deployment behavior.

Usage:
    python3 scripts/generate_paper_benchmark_table.py \
        --orig_dir data/test_orig --ai_dir data/test_ai \
        --unrelated_dir data/test_unrelated --max 25
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


def wilson_ci(successes, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z ** 2 / n
    centre = p + z ** 2 / (2 * n)
    margin = z * math.sqrt((p * (1 - p) + z ** 2 / (4 * n)) / n)
    return ((centre - margin) / denom, (centre + margin) / denom)


def mean_std(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return (float("nan"), float("nan"))
    return (float(np.mean(vals)), float(np.std(vals)))


# ── Attack generators ─────────────────────────────────────────────────────
def attack_jpeg(img, q):
    ok, enc = cv2.imencode(".jpg", img, [int(cv2.IMWRITE_JPEG_QUALITY), q])
    return cv2.imdecode(enc, cv2.IMREAD_COLOR)


def attack_resize_true(img, scale):
    h, w = img.shape[:2]
    return cv2.resize(img, (max(1, int(w * scale)), max(1, int(h * scale))))


def attack_crop_true(img, crop_pct):
    h, w = img.shape[:2]
    ch = int(h * crop_pct)
    return img[ch:, :]


def attack_rotate_true(img, degrees):
    h, w = img.shape[:2]
    M = cv2.getRotationMatrix2D((w / 2, h / 2), degrees, 1.0)
    return cv2.warpAffine(img, M, (w, h), borderMode=cv2.BORDER_REFLECT)


def attack_brightness(img, factor):
    return np.clip(img.astype(np.float32) * factor, 0, 255).astype(np.uint8)


def attack_contrast(img, alpha):
    return np.clip(128 + alpha * (img.astype(np.float32) - 128), 0, 255).astype(np.uint8)


ROBUSTNESS_CONDITIONS = {
    # name -> transform fn applied to the SIGNED image
    "Untouched Signed":  lambda im: im.copy(),
    "JPEG Q=90":         lambda im: attack_jpeg(im, 90),
    "JPEG Q=75":         lambda im: attack_jpeg(im, 75),
    "JPEG Q=50":         lambda im: attack_jpeg(im, 50),
    "Brightness (+20%)": lambda im: attack_brightness(im, 1.20),
    "Contrast (1.25x)":  lambda im: attack_contrast(im, 1.25),
}

DETECTION_CONDITIONS_BASE = {
    "True Resize (0.75x)": lambda im: attack_resize_true(im, 0.75),
    "True Crop (top 10%)": lambda im: attack_crop_true(im, 0.10),
    "Rotation (5 deg)":    lambda im: attack_rotate_true(im, 5),
}


def evaluate_one(orig_bgr, suspect_bgr, master_seed):
    """One full pass of the proposed pipeline: structural NC + seal check."""
    _, _, m_buffer = phase1_ai_roi_isolation(orig_bgr)
    w_key_reg, p_anchors, _, _, _ = register_master_key_v3(orig_bgr, m_buffer, master_seed=master_seed)
    signed_img, tamper_hash = embed_tamper_signature(orig_bgr, master_seed=master_seed)
    return m_buffer, w_key_reg, p_anchors, signed_img, tamper_hash


def check_suspect(suspect_bgr, orig_shape, m_buffer, w_key_reg, p_anchors, tamper_hash, master_seed):
    key_susp = extract_key_v3(suspect_bgr, m_buffer, p_anchors, w_key_reg, orig_shape)
    nc = compute_nc(w_key_reg, key_susp)
    bit_acc = float(np.mean(w_key_reg == key_susp)) * 100.0
    seal = verify_tamper_signature(suspect_bgr, tamper_hash, orig_shape, master_seed=master_seed)
    return {"nc": nc, "bit_acc": bit_acc, "seal_intact": seal["seal_intact"],
            "seal_bit_acc": seal.get("seal_bit_acc"), "resized": seal.get("resized", False)}


def run(orig_dir, ai_dir, unrelated_dir, max_images, out_csv, seed_override=None):
    orig_files = sorted(glob.glob(os.path.join(orig_dir, "*.*")))
    orig_files = [f for f in orig_files if os.path.splitext(f)[1].lower() in (".png", ".jpg", ".jpeg")][:max_images]
    if not orig_files:
        print(f"No images found in {orig_dir}")
        return

    from watermark.crypto_vault import get_master_seed
    master_seed = seed_override if seed_override is not None else get_master_seed()
    print(f"Using master_seed={master_seed} (from unlocked vault unless --seed_override was given)")

    rows = []
    print(f"Evaluating {len(orig_files)} scene(s) ...")
    for idx, orig_path in enumerate(orig_files, 1):
        stem = os.path.splitext(os.path.basename(orig_path))[0]
        orig = cv2.imread(orig_path)
        if orig is None:
            continue
        print(f"[{idx:02d}/{len(orig_files):02d}] {stem} ... ", end="", flush=True)

        m_buffer, w_key_reg, p_anchors, signed_img, tamper_hash = evaluate_one(orig, None, master_seed)
        base_psnr = compute_psnr(orig, signed_img)
        base_ssim = compute_ssim(orig, signed_img)

        # ── Robustness conditions (benign edits, applied to the SIGNED image) ──
        for cond_name, fn in ROBUSTNESS_CONDITIONS.items():
            suspect = fn(signed_img)
            r = check_suspect(suspect, orig.shape, m_buffer, w_key_reg, p_anchors, tamper_hash, master_seed)
            rows.append({"image": stem, "table": "robustness", "condition": cond_name,
                          "nc": r["nc"], "bit_acc": r["bit_acc"], "seal_intact": r["seal_intact"],
                          "seal_bit_acc": r["seal_bit_acc"], "resized": r["resized"],
                          "nc_retained": r["nc"] >= config.NC_THRESHOLD,
                          "watermarked_psnr_db": round(base_psnr, 2), "watermarked_ssim": round(base_ssim, 4)})

        # ── Detection conditions: geometric attacks (malicious-shape, ground truth = SHOULD be flagged) ──
        for cond_name, fn in DETECTION_CONDITIONS_BASE.items():
            suspect = fn(signed_img)
            r = check_suspect(suspect, orig.shape, m_buffer, w_key_reg, p_anchors, tamper_hash, master_seed)
            flagged = (not r["seal_intact"]) or (r["nc"] < config.NC_THRESHOLD)
            rows.append({"image": stem, "table": "detection", "condition": cond_name,
                          "nc": r["nc"], "bit_acc": r["bit_acc"], "seal_intact": r["seal_intact"],
                          "seal_bit_acc": r["seal_bit_acc"], "resized": r["resized"],
                          "flagged": flagged, "ground_truth_should_flag": True})

        # ── AI regeneration (real paired image, if provided) ─────────────
        if ai_dir:
            ai_matches = glob.glob(os.path.join(ai_dir, f"{stem}.*")) or glob.glob(os.path.join(ai_dir, f"{stem}_*.*"))
            if ai_matches:
                ai_img = cv2.imread(ai_matches[0])
                if ai_img is not None:
                    r = check_suspect(ai_img, orig.shape, m_buffer, w_key_reg, p_anchors, tamper_hash, master_seed)
                    flagged = (not r["seal_intact"]) or (r["nc"] < config.NC_THRESHOLD)
                    rows.append({"image": stem, "table": "detection", "condition": "AI-Regeneration (real)",
                                  "nc": r["nc"], "bit_acc": r["bit_acc"], "seal_intact": r["seal_intact"],
                                  "seal_bit_acc": r["seal_bit_acc"], "resized": r["resized"],
                                  "flagged": flagged, "ground_truth_should_flag": True})

        # ── Unrelated image negative-style control (still SHOULD be flagged - never registered) ──
        if unrelated_dir:
            u_files = sorted(glob.glob(os.path.join(unrelated_dir, "*.*")))
            u_files = [f for f in u_files if os.path.splitext(f)[1].lower() in (".png", ".jpg", ".jpeg")]
            if u_files:
                u_img = cv2.imread(u_files[idx % len(u_files)])
                if u_img is not None:
                    r = check_suspect(u_img, orig.shape, m_buffer, w_key_reg, p_anchors, tamper_hash, master_seed)
                    flagged = (not r["seal_intact"]) or (r["nc"] < config.NC_THRESHOLD)
                    rows.append({"image": stem, "table": "detection", "condition": "Unrelated Image (never registered)",
                                  "nc": r["nc"], "bit_acc": r["bit_acc"], "seal_intact": r["seal_intact"],
                                  "seal_bit_acc": r["seal_bit_acc"], "resized": r["resized"],
                                  "flagged": flagged, "ground_truth_should_flag": True})

        print("done")

    if not rows:
        print("No results produced.")
        return

    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=sorted({k for r in rows for k in r.keys()}))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nRaw per-image data -> {out_csv}")

    n_images = len({r["image"] for r in rows})

    # ── TABLE 1: Robustness (ownership retention under benign edits) ────────
    print("\n" + "=" * 100)
    print(f"  TABLE 1: OWNERSHIP RETENTION UNDER BENIGN OPERATIONS  (N={n_images} scenes)")
    print("=" * 100)
    print(f"{'Condition':<22} | {'Mean NC':<16} | {'Bit Acc':<10} | {'NC Retained (95% CI)':<24} | {'Seal Bit Acc':<14}")
    print("-" * 100)
    for cond in ROBUSTNESS_CONDITIONS:
        sub = [r for r in rows if r["table"] == "robustness" and r["condition"] == cond]
        nc_mean, nc_std = mean_std([r["nc"] for r in sub])
        acc_mean, _ = mean_std([r["bit_acc"] for r in sub])
        retained = sum(1 for r in sub if r["nc_retained"])
        lo, hi = wilson_ci(retained, len(sub))
        seal_mean, _ = mean_std([r["seal_bit_acc"] for r in sub])
        print(f"{cond:<22} | {nc_mean:.4f}+-{nc_std:.3f}  | {acc_mean:6.2f}%   | "
              f"{100*retained/len(sub):5.1f}% [{100*lo:.0f}-{100*hi:.0f}]        | "
              f"{(f'{seal_mean:.1f}%' if not math.isnan(seal_mean) else 'n/a'):<14}")
    print("=" * 100)

    # ── TABLE 2: Detection (should-be-flagged conditions) ───────────────────
    all_detection_conditions = list(DETECTION_CONDITIONS_BASE.keys())
    if any(r["condition"] == "AI-Regeneration (real)" for r in rows):
        all_detection_conditions.append("AI-Regeneration (real)")
    if any(r["condition"] == "Unrelated Image (never registered)" for r in rows):
        all_detection_conditions.append("Unrelated Image (never registered)")

    print("\n" + "=" * 100)
    print(f"  TABLE 2: DETECTION RATE ON CONTENT THAT SHOULD BE FLAGGED  (N={n_images} scenes)")
    print("=" * 100)
    print(f"{'Condition':<34} | {'Mean NC':<16} | {'Flagged (95% Wilson CI)':<28}")
    print("-" * 100)
    for cond in all_detection_conditions:
        sub = [r for r in rows if r["table"] == "detection" and r["condition"] == cond]
        if not sub:
            continue
        nc_mean, nc_std = mean_std([r["nc"] for r in sub])
        flagged = sum(1 for r in sub if r["flagged"])
        lo, hi = wilson_ci(flagged, len(sub))
        print(f"{cond:<34} | {nc_mean:+.4f}+-{nc_std:.3f}  | "
              f"{100*flagged/len(sub):5.1f}% [{100*lo:.0f}-{100*hi:.0f}]  (n={len(sub)})")
    print("=" * 100)
    print("NOTE: near-zero NC on AI-regen / unrelated-image rows reflects the noise floor for")
    print("'this is a substantially different image', not fine-grained attack discrimination -")
    print("say so explicitly in the paper rather than implying these prove targeted detection.")

    # ── LaTeX (IEEE two-column friendly, booktabs style) ─────────────────────
    print("\n" + "=" * 100)
    print("  LATEX - TABLE 1 (paste into Overleaf; requires \\usepackage{booktabs})")
    print("=" * 100)
    print("\\begin{table}[t]")
    print(f"\\caption{{Ownership retention under benign operations ($N={n_images}$).}}")
    print("\\centering")
    print("\\begin{tabular}{lccc}")
    print("\\toprule")
    print("Condition & Mean NC & Bit Acc (\\%) & Retained (\\%) \\\\")
    print("\\midrule")
    for cond in ROBUSTNESS_CONDITIONS:
        sub = [r for r in rows if r["table"] == "robustness" and r["condition"] == cond]
        nc_mean, _ = mean_std([r["nc"] for r in sub])
        acc_mean, _ = mean_std([r["bit_acc"] for r in sub])
        retained = sum(1 for r in sub if r["nc_retained"])
        print(f"{cond} & {nc_mean:.3f} & {acc_mean:.1f} & {100*retained/len(sub):.1f} \\\\")
    print("\\bottomrule")
    print("\\end{tabular}")
    print("\\end{table}")

    print("\n" + "=" * 100)
    print("  LATEX - TABLE 2")
    print("=" * 100)
    print("\\begin{table}[t]")
    print(f"\\caption{{Detection rate on content that should be flagged ($N={n_images}$), with 95\\% Wilson CIs.}}")
    print("\\centering")
    print("\\begin{tabular}{lccc}")
    print("\\toprule")
    print("Condition & Mean NC & Flagged (\\%) & 95\\% CI \\\\")
    print("\\midrule")
    for cond in all_detection_conditions:
        sub = [r for r in rows if r["table"] == "detection" and r["condition"] == cond]
        if not sub:
            continue
        nc_mean, _ = mean_std([r["nc"] for r in sub])
        flagged = sum(1 for r in sub if r["flagged"])
        lo, hi = wilson_ci(flagged, len(sub))
        print(f"{cond} & {nc_mean:.3f} & {100*flagged/len(sub):.1f} & [{100*lo:.0f}, {100*hi:.0f}] \\\\")
    print("\\bottomrule")
    print("\\end{tabular}")
    print("\\end{table}")
    print("=" * 100)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--orig_dir", required=True)
    ap.add_argument("--ai_dir", default=None)
    ap.add_argument("--unrelated_dir", default=None)
    ap.add_argument("--max", type=int, default=25)
    ap.add_argument("--seed_override", type=int, default=None,
                     help="Override the vault's real master seed for this run only "
                          "(for testing reproducibility across seeds). Omit to use the "
                          "real unlocked vault seed - the number that should go in the paper.")
    ap.add_argument("--out_csv", default=os.path.join(config.DATA_DIR, "paper_benchmark_raw.csv"))
    ap.add_argument("--passphrase", "-p", default=None)
    args = ap.parse_args()

    load_secrets(args.passphrase)
    run(args.orig_dir, args.ai_dir, args.unrelated_dir, args.max, args.out_csv, args.seed_override)