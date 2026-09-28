#!/usr/bin/env python3
"""
generate_paper_benchmark_table.py — Comprehensive Forensic Benchmark Generator
Uses:
  1. Real AI-regenerated images from your AI dataset folder (--ai_dir).
  2. Programmatically simulated distortion attacks (JPEG Q75, Q50, Scaling, Brightness, Contrast, Crop).

Outputs:
  - Terminal Benchmark Summary
  - LaTeX Table Code formatted for IEEE / CVPR papers.

Usage:
    python3 scripts/generate_paper_benchmark_table.py --orig_dir data/test_orig --ai_dir data/test_ai --max 50
"""
import os
import sys
import glob
import argparse
import time
import cv2
import numpy as np


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from watermark.crypto_vault import load_secrets  # <--- ADD THIS IMPORT
from watermark.zero_watermark import (
    phase1_ai_roi_isolation, register_master_key_v3, extract_key_v3, compute_nc
)
from watermark.tamper_seal import embed_tamper_signature, verify_tamper_signature
from watermark.metrics import compute_psnr, compute_ssim


# ── Distortion Generators (Standard Transformations) ────────────────────────
def attack_jpeg(img, quality=75):
    ok, enc = cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
    return cv2.imdecode(enc, cv2.IMREAD_COLOR)

def attack_scaling(img, scale=0.75):
    h, w = img.shape[:2]
    small = cv2.resize(img, (int(w * scale), int(h * scale)))
    return cv2.resize(small, (w, h))

def attack_brightness(img, factor=1.25):
    return np.clip(img.astype(np.float32) * factor, 0, 255).astype(np.uint8)

def attack_contrast(img, alpha=1.3):
    return np.clip(128 + alpha * (img.astype(np.float32) - 128), 0, 255).astype(np.uint8)

def attack_crop(img, crop_pct=0.10):
    h, w = img.shape[:2]
    ch = int(h * crop_pct)
    out = img.copy()
    out[:ch, :] = 0  # Black out top 10%
    return out


# ── Main Benchmark Engine ───────────────────────────────────────────────────
def run_benchmark(orig_dir, ai_dir, max_images=50):
    orig_files = sorted(glob.glob(os.path.join(orig_dir, "*.*")))
    orig_files = [f for f in orig_files if os.path.splitext(f)[1].lower() in (".png", ".jpg", ".jpeg")][:max_images]

    if not orig_files:
        print(f"❌ No images found in {orig_dir}")
        return

    print("=" * 85)
    print(f"🔬 RUNNING FORENSIC BENCHMARK EVALUATION ({len(orig_files)} SCENES)")
    print(f"   Original Clean Images : {orig_dir}")
    print(f"   Real AI-Regenerated   : {ai_dir}")
    print("=" * 85)

    distortion_attacks = {
        "JPEG (Q=75)": lambda im: attack_jpeg(im, 75),
        "JPEG (Q=50)": lambda im: attack_jpeg(im, 50),
        "Scaling (0.75x)": attack_scaling,
        "Brightness (+25%)": attack_brightness,
        "Contrast (1.3x)": attack_contrast,
        "Cropout (10%)": attack_crop,
    }

    # Tracking metrics
    all_categories = ["AI-Regeneration (Real)"] + list(distortion_attacks.keys())
    results = {cat: {"tpr": 0, "nc": [], "psnr": [], "ssim": [], "bit_acc": []} for cat in all_categories}

    # Baseline visual fidelity (Watermarked vs Original)
    baseline_psnr = []
    baseline_ssim = []

    matched_count = 0

    for idx, orig_path in enumerate(orig_files, 1):
        base_name = os.path.splitext(os.path.basename(orig_path))[0]
        orig_img = cv2.imread(orig_path)
        if orig_img is None:
            continue

        # Look for matching AI-regenerated file in ai_dir
        # matches: base_name.png, base_name_ai.png, etc.
        ai_matches = glob.glob(os.path.join(ai_dir, f"{base_name}*.*"))
        if not ai_matches:
            # Fallback: check if files are identically named
            exact_path = os.path.join(ai_dir, os.path.basename(orig_path))
            if os.path.exists(exact_path):
                ai_matches = [exact_path]

        if not ai_matches:
            print(f"⚠️  [{idx:02d}] No matching AI image found for {base_name}, skipping...")
            continue

        ai_img = cv2.imread(ai_matches[0])
        if ai_img is None:
            continue

        matched_count += 1
        print(f"[{matched_count:02d}/{len(orig_files):02d}] Processing {base_name} ... ", end="", flush=True)

        # ── 1. Registration ─────────────────────────────────────────────────
        _, _, m_buffer = phase1_ai_roi_isolation(orig_img)
        w_key_reg, p_anchors, _, _, _ = register_master_key_v3(orig_img, m_buffer)
        signed_img, tamper_hash = embed_tamper_signature(orig_img)

        # Record watermarked visual quality
        baseline_psnr.append(compute_psnr(orig_img, signed_img))
        baseline_ssim.append(compute_ssim(orig_img, signed_img))

        # ── 2. Test Real AI-Regeneration Attack ──────────────────────────────
        key_ai = extract_key_v3(ai_img, m_buffer, p_anchors, w_key_reg, orig_img.shape)
        nc_ai = compute_nc(w_key_reg, key_ai)
        acc_ai = float(np.mean(w_key_reg == key_ai)) * 100.0
        seal_ai = verify_tamper_signature(ai_img, tamper_hash, orig_img.shape)

        results["AI-Regeneration (Real)"]["nc"].append(nc_ai)
        results["AI-Regeneration (Real)"]["bit_acc"].append(acc_ai)
        results["AI-Regeneration (Real)"]["psnr"].append(compute_psnr(orig_img, ai_img))
        results["AI-Regeneration (Real)"]["ssim"].append(compute_ssim(orig_img, ai_img))

        # AI attack correctly flagged as tampered:
        # Either seal is broken or NC indicates modified scene
        if not seal_ai["seal_intact"] or nc_ai < config.NC_THRESHOLD:
            results["AI-Regeneration (Real)"]["tpr"] += 1

        # ── 3. Test Distortion Attacks ───────────────────────────────────────
        for name, fn in distortion_attacks.items():
            distorted = fn(signed_img)
            key_dist = extract_key_v3(distorted, m_buffer, p_anchors, w_key_reg, orig_img.shape)
            nc_dist = compute_nc(w_key_reg, key_dist)
            acc_dist = float(np.mean(w_key_reg == key_dist)) * 100.0
            seal_dist = verify_tamper_signature(distorted, tamper_hash, orig_img.shape)

            results[name]["nc"].append(nc_dist)
            results[name]["bit_acc"].append(acc_dist)
            results[name]["psnr"].append(compute_psnr(orig_img, distorted))
            results[name]["ssim"].append(compute_ssim(orig_img, distorted))

            # Benign transforms survive (NC >= threshold)
            # Cropout is malicious tampering -> correctly flagged if seal broken or NC dropped
            if "Cropout" in name:
                if not seal_dist["seal_intact"] or nc_dist < config.NC_THRESHOLD:
                    results[name]["tpr"] += 1
            else:
                if nc_dist >= config.NC_THRESHOLD:
                    results[name]["tpr"] += 1

        print("Done.")

    if matched_count == 0:
        print("❌ No matching image pairs processed.")
        return

    # ── Final Summary Display ────────────────────────────────────────────────
    avg_psnr_w = np.mean(baseline_psnr)
    avg_ssim_w = np.mean(baseline_ssim)

    print("\n" + "=" * 95)
    print(f"  BENCHMARK SUMMARY RESULTS across {matched_count} Traffic Camera Scenes")
    print(f"  Watermark Visual Fidelity: PSNR = {avg_psnr_w:.2f} dB,  SSIM = {avg_ssim_w:.4f}")
    print("=" * 95)
    print(f"{'Attack / Distortion Category':<28} | {'Mean NC Score':<15} | {'Mean Bit Acc':<15} | {'TPR (%)':<12}")
    print("-" * 95)

    for cat in all_categories:
        avg_nc = np.mean(results[cat]["nc"])
        avg_acc = np.mean(results[cat]["bit_acc"])
        tpr_pct = (results[cat]["tpr"] / matched_count) * 100.0
        print(f"{cat:<28} | {avg_nc:.4f}          | {avg_acc:.2f}%         | {tpr_pct:.1f}%")

    print("=" * 95)

    # ── Print Ready-to-Use LaTeX Table Code ──────────────────────────────────
    print("\n" + "=" * 95)
    print("  LATEX CODE (Copy directly into Overleaf for your research paper)")
    print("=" * 95)
    print("\\begin{table*}[t]")
    print("\\centering")
    print(f"\\caption{{Forensic Performance, Robustness (TPR\\%), and NC Scores across {matched_count} Surveillance Scenes.}}")
    print("\\begin{tabular}{l c c c c c c c}")
    print("\\hline")
    print("Metric & AI-Regen & JPEG (Q=75) & JPEG (Q=50) & Scaling & Brightness & Contrast & Cropout \\\\")
    print("\\hline")

    tpr_row = "Detection / TPR (\\%)"
    for cat in all_categories:
        tpr_pct = (results[cat]["tpr"] / matched_count) * 100.0
        tpr_row += f" & {tpr_pct:.1f}\\%"
    tpr_row += " \\\\"
    print(tpr_row)

    nc_row = "Mean NC Score"
    for cat in all_categories:
        avg_nc = np.mean(results[cat]["nc"])
        nc_row += f" & {avg_nc:.3f}"
    nc_row += " \\\\"
    print(nc_row)

    print("\\hline")
    print("\\end{tabular}")
    print("\\end{table*}")
    print("=" * 95)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Forensics Benchmark Table Generator")
    parser.add_argument("--orig_dir", required=True, help="Folder of original clean images")
    parser.add_argument("--ai_dir", required=True, help="Folder of corresponding AI-regenerated images")
    parser.add_argument("--max", type=int, default=50, help="Max images to evaluate (default: 50)")
    parser.add_argument("--passphrase", "-p", default=None, help="Vault passphrase (omit to be prompted)")
    args = parser.parse_args()

    # UNLOCK SECRETS FIRST
    load_secrets(args.passphrase)

    run_benchmark(args.orig_dir, args.ai_dir, max_images=args.max)