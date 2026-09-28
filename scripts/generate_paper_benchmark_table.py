#!/usr/bin/env python3
"""
generate_paper_benchmark_table.py — Scientifically Rigorous Forensics Benchmark

Produces Two Distinct Tables:
  - TABLE 1: Robustness & Ownership Retention under Benign Processing
  - TABLE 2: Tamper Detection & Localization under Malicious Attacks & Controls

Usage:
    python3 scripts/generate_paper_benchmark_table.py --orig_dir ori_data --ai_dir ai_dir --unrelated_dir test --max 25
"""
import os
import sys
import glob
import argparse
import time
import cv2
import numpy as np

# Setup python path to import watermark modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from watermark.crypto_vault import load_secrets
from watermark.zero_watermark import (
    phase1_ai_roi_isolation, register_master_key_v3, extract_key_v3, compute_nc
)
from watermark.tamper_seal import embed_tamper_signature, verify_tamper_signature
from watermark.metrics import compute_psnr, compute_ssim


# ==============================================================================
# 1. BENIGN TRANSFORMATIONS (Evaluating Robustness)
# ==============================================================================
def transform_jpeg(img, quality):
    ok, enc = cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
    return cv2.imdecode(enc, cv2.IMREAD_COLOR)

def transform_true_resize(img, scale=0.75):
    """Genuinely smaller dimensions to exercise scale_r/scale_c remapping."""
    h, w = img.shape[:2]
    return cv2.resize(img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)

def transform_brightness(img, factor=1.20):
    return np.clip(img.astype(np.float32) * factor, 0, 255).astype(np.uint8)

def transform_contrast(img, alpha=1.25):
    return np.clip(128 + alpha * (img.astype(np.float32) - 128), 0, 255).astype(np.uint8)


# ==============================================================================
# 2. MALICIOUS ATTACKS (Evaluating Tamper Detection)
# ==============================================================================
def attack_true_crop(img, crop_pct=0.10):
    """True geometric crop: trims pixels from top/left borders, changing dimensions."""
    h, w = img.shape[:2]
    ch, cw = int(h * crop_pct), int(w * crop_pct)
    return img[ch:, cw:].copy()


# ==============================================================================
# BENCHMARK SUITE
# ==============================================================================
def run_rigorous_benchmark(orig_dir, ai_dir, unrelated_dir=None, max_images=25):
    orig_files = sorted(glob.glob(os.path.join(orig_dir, "*.*")))
    orig_files = [f for f in orig_files if os.path.splitext(f)[1].lower() in (".png", ".jpg", ".jpeg")][:max_images]

    if not orig_files:
        print(f"❌ No images found in {orig_dir}")
        return

    print("=" * 90)
    print(f"🔬 RUNNING SCIENTIFIC FORENSICS BENCHMARK SUITE ({len(orig_files)} SCENES)")
    print(f"   Originals Clean : {orig_dir}")
    print(f"   Real AI-Edited  : {ai_dir}")
    if unrelated_dir:
        print(f"   Unrelated Control: {unrelated_dir}")
    print("=" * 90)

    # Benign transforms: we EXPECT ownership (NC) and semi-fragile seal to SURVIVE
    benign_transforms = {
        "Untouched Signed": lambda im: im.copy(),
        "JPEG (Q=90)": lambda im: transform_jpeg(im, 90),
        "JPEG (Q=75)": lambda im: transform_jpeg(im, 75),
        "JPEG (Q=50)": lambda im: transform_jpeg(im, 50),
        "True Resize (0.75x)": transform_true_resize,
        "Brightness (+20%)": transform_brightness,
        "Contrast (1.25x)": transform_contrast,
    }

    benign_results = {k: {"nc": [], "bit_acc": [], "seal_acc": [], "seal_pass": 0, "nc_pass": 0} for k in benign_transforms}

    # Malicious attacks: we EXPECT detection (seal broken OR NC degraded)
    attack_categories = ["AI-Regeneration (Real)", "True Border Crop (10%)"]
    if unrelated_dir:
        attack_categories.append("Unrelated Image (Negative Control)")

    malicious_results = {k: {"nc": [], "bit_acc": [], "detected": 0} for k in attack_categories}

    # Unrelated control files
    unrelated_files = []
    if unrelated_dir:
        unrelated_files = sorted(glob.glob(os.path.join(unrelated_dir, "*.*")))
        unrelated_files = [f for f in unrelated_files if os.path.splitext(f)[1].lower() in (".png", ".jpg", ".jpeg")]

    valid_scenes = 0

    for idx, orig_path in enumerate(orig_files, 1):
        filename = os.path.basename(orig_path)
        stem = os.path.splitext(filename)[0]

        # Exact stem matching for AI image
        ai_path = os.path.join(ai_dir, filename)
        if not os.path.exists(ai_path):
            ai_matches = glob.glob(os.path.join(ai_dir, f"{stem}_*.*"))
            if ai_matches:
                ai_path = ai_matches[0]
            else:
                print(f"⚠️  [{idx:02d}] Missing AI counterpart for {stem}, skipping...")
                continue

        orig_img = cv2.imread(orig_path)
        ai_img = cv2.imread(ai_path)
        if orig_img is None or ai_img is None:
            continue

        valid_scenes += 1
        print(f"[{valid_scenes:02d}/{len(orig_files):02d}] Evaluating {stem} ... ", end="", flush=True)

        # ── 1. Registration ─────────────────────────────────────────────────
        _, _, m_buffer = phase1_ai_roi_isolation(orig_img)
        w_key_reg, p_anchors, _, _, _ = register_master_key_v3(orig_img, m_buffer)
        signed_img, tamper_hash = embed_tamper_signature(orig_img)

        # ── 2. Run Benign Transformations (Table 1 Data) ─────────────────────
        for b_name, b_fn in benign_transforms.items():
            trans_img = b_fn(signed_img)

            # Verification
            w_key_ext = extract_key_v3(trans_img, m_buffer, p_anchors, w_key_reg, orig_img.shape)
            nc = compute_nc(w_key_reg, w_key_ext)
            bit_acc = float(np.mean(w_key_reg == w_key_ext)) * 100.0
            seal = verify_tamper_signature(trans_img, tamper_hash, orig_img.shape)

            benign_results[b_name]["nc"].append(nc)
            benign_results[b_name]["bit_acc"].append(bit_acc)
            benign_results[b_name]["seal_acc"].append(seal.get("seal_bit_acc", 0.0))
            if nc >= config.NC_THRESHOLD:
                benign_results[b_name]["nc_pass"] += 1
            if seal["seal_intact"]:
                benign_results[b_name]["seal_pass"] += 1

        # ── 3. Run Malicious Attacks (Table 2 Data) ──────────────────────────
        # A. Real AI Regeneration
        w_ai = extract_key_v3(ai_img, m_buffer, p_anchors, w_key_reg, orig_img.shape)
        nc_ai = compute_nc(w_key_reg, w_ai)
        bit_acc_ai = float(np.mean(w_key_reg == w_ai)) * 100.0
        seal_ai = verify_tamper_signature(ai_img, tamper_hash, orig_img.shape)

        malicious_results["AI-Regeneration (Real)"]["nc"].append(nc_ai)
        malicious_results["AI-Regeneration (Real)"]["bit_acc"].append(bit_acc_ai)
        # Detected if seal broken OR NC collapsed below ownership threshold
        if (not seal_ai["seal_intact"]) or (nc_ai < config.NC_THRESHOLD):
            malicious_results["AI-Regeneration (Real)"]["detected"] += 1

        # B. True Border Crop
        crop_img = attack_true_crop(signed_img, 0.10)
        w_crop = extract_key_v3(crop_img, m_buffer, p_anchors, w_key_reg, orig_img.shape)
        nc_crop = compute_nc(w_key_reg, w_crop)
        bit_acc_crop = float(np.mean(w_key_reg == w_crop)) * 100.0
        seal_crop = verify_tamper_signature(crop_img, tamper_hash, orig_img.shape)

        malicious_results["True Border Crop (10%)"]["nc"].append(nc_crop)
        malicious_results["True Border Crop (10%)"]["bit_acc"].append(bit_acc_crop)
        if (not seal_crop["seal_intact"]) or (nc_crop < config.NC_THRESHOLD):
            malicious_results["True Border Crop (10%)"]["detected"] += 1

        # C. Negative Control: Unrelated Image
        if unrelated_files:
            unrel_path = unrelated_files[idx % len(unrelated_files)]
            unrel_img = cv2.imread(unrel_path)
            if unrel_img is not None:
                w_unrel = extract_key_v3(unrel_img, m_buffer, p_anchors, w_key_reg, orig_img.shape)
                nc_unrel = compute_nc(w_key_reg, w_unrel)
                bit_acc_unrel = float(np.mean(w_key_reg == w_unrel)) * 100.0
                seal_unrel = verify_tamper_signature(unrel_img, tamper_hash, orig_img.shape)

                malicious_results["Unrelated Image (Negative Control)"]["nc"].append(nc_unrel)
                malicious_results["Unrelated Image (Negative Control)"]["bit_acc"].append(bit_acc_unrel)
                # Correctly handled if rejected as NOT_REGISTERED (NC < 0.50)
                if nc_unrel < 0.50:
                    malicious_results["Unrelated Image (Negative Control)"]["detected"] += 1

        print("Done.")

    if valid_scenes == 0:
        print("❌ No matching image pairs were found.")
        return

    # ==============================================================================
    # PRINT RESULTS: TABLE 1 (ROBUSTNESS / BENIGN)
    # ==============================================================================
    print("\n" + "=" * 95)
    print(f"TABLE 1: BENIGN TRANSFORMATIONS (Ownership Retention across {valid_scenes} Scenes)")
    print("=" * 95)
    print(f"{'Transformation':<24} | {'Mean NC Score':<16} | {'Watermark Acc':<14} | {'Seal Bit Acc':<14} | {'Seal Survival %':<16}")
    print("-" * 95)
    for b_name in benign_transforms:
        avg_nc = f"{np.mean(benign_results[b_name]['nc']):.4f} ± {np.std(benign_results[b_name]['nc']):.3f}"
        avg_acc = f"{np.mean(benign_results[b_name]['bit_acc']):.2f}%"
        avg_seal = f"{np.mean(benign_results[b_name]['seal_acc']):.2f}%"
        seal_ret = f"{(benign_results[b_name]['seal_pass'] / valid_scenes) * 100:.1f}%"
        print(f"{b_name:<24} | {avg_nc:<16} | {avg_acc:<14} | {avg_seal:<14} | {seal_ret:<16}")
    print("=" * 95)

    # ==============================================================================
    # PRINT RESULTS: TABLE 2 (MALICIOUS ATTACKS & CONTROLS)
    # ==============================================================================
    print("\n" + "=" * 90)
    print(f"TABLE 2: MALICIOUS ATTACKS & CONTROLS (Forensic Tamper Detection across {valid_scenes} Scenes)")
    print("=" * 90)
    print(f"{'Attack / Scenario':<36} | {'Mean NC Score':<16} | {'Bit Accuracy':<14} | {'Tamper Detection Rate (%)':<25}")
    print("-" * 90)
    for m_name in attack_categories:
        avg_nc = f"{np.mean(malicious_results[m_name]['nc']):.4f} ± {np.std(malicious_results[m_name]['nc']):.3f}"
        avg_acc = f"{np.mean(malicious_results[m_name]['bit_acc']):.2f}%"
        det_pct = f"{(malicious_results[m_name]['detected'] / valid_scenes) * 100:.1f}% ({malicious_results[m_name]['detected']}/{valid_scenes})"
        print(f"{m_name:<36} | {avg_nc:<16} | {avg_acc:<14} | {det_pct:<25}")
    print("=" * 90)

    # ==============================================================================
    # PRINT LATEX FORMATTED CODE (Ready to paste into Overleaf)
    # ==============================================================================
    print("\n" + "=" * 90)
    print("  LATEX CODE FOR OVERLEAF (TABLE 1: BENIGN ROBUSTNESS)")
    print("=" * 90)
    print("\\begin{table}[h]")
    print("\\centering")
    print(f"\\caption{{Ownership Retention under Benign Operations ($N={valid_scenes}$).}}")
    print("\\begin{tabular}{l c c c}")
    print("\\hline")
    print("Transformation & Mean NC & Bit Acc (\\%) & NC Retention (\\%) \\\\")
    print("\\hline")
    for b_name in benign_transforms:
        m_nc = np.mean(benign_results[b_name]['nc'])
        m_acc = np.mean(benign_results[b_name]['bit_acc'])
        ret = (benign_results[b_name]['nc_pass'] / valid_scenes) * 100.0
        print(f"{b_name} & {m_nc:.3f} & {m_acc:.1f}\\% & {ret:.1f}\\% \\\\")
    print("\\hline")
    print("\\end{tabular}")
    print("\\end{table}")

    print("\n" + "=" * 90)
    print("  LATEX CODE FOR OVERLEAF (TABLE 2: TAMPER DETECTION & CONTROLS)")
    print("=" * 90)
    print("\\begin{table}[h]")
    print("\\centering")
    print(f"\\caption{{Forensic Tamper Detection and Open-World Rejection ($N={valid_scenes}$).}}")
    print("\\begin{tabular}{l c c c}")
    print("\\hline")
    print("Scenario & Mean NC & Bit Acc (\\%) & Detection / Rejection Rate (\\%) \\\\")
    print("\\hline")
    for m_name in attack_categories:
        m_nc = np.mean(malicious_results[m_name]['nc'])
        m_acc = np.mean(malicious_results[m_name]['bit_acc'])
        det = (malicious_results[m_name]['detected'] / valid_scenes) * 100.0
        print(f"{m_name} & {m_nc:.3f} & {m_acc:.1f}\\% & {det:.1f}\\% \\\\")
    print("\\hline")
    print("\\end{tabular}")
    print("\\end{table}")
    print("=" * 90)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scientifically Rigorous Benchmark Table Generator")
    parser.add_argument("--orig_dir", required=True, help="Folder of clean original images")
    parser.add_argument("--ai_dir", required=True, help="Folder of real AI-regenerated images")
    parser.add_argument("--unrelated_dir", default=None, help="Folder of unrelated images for negative control")
    parser.add_argument("--max", type=int, default=25, help="Number of scenes to evaluate")
    parser.add_argument("--passphrase", "-p", default=None, help="Vault passphrase (omit to be prompted)")
    args = parser.parse_args()

    # Load vault secrets first
    load_secrets(args.passphrase)

    run_rigorous_benchmark(args.orig_dir, args.ai_dir, args.unrelated_dir, max_images=args.max)