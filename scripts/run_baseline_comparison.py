#!/usr/bin/env python3
"""
run_baseline_comparison.py — Automated Comparative Baseline Evaluation
Compares our proposed framework against 3 established forensic/watermarking baselines:
  1. Global DWT-DCT (Ablation — No YOLO ROI isolation)
  2. Classical ELA (Error Level Analysis — JPEG compression anomaly detector)
  3. Rel-Zero (CVPR 2026 concept — Relational patch-pair feature invariance)
  4. Proposed Framework (Ours — YOLOv8 Semantic ROI + DWT-DCT + QIM Seal)

Usage:
    python3 scripts/run_baseline_comparison.py --orig_dir ori_data --ai_dir ai_dir --max 25
"""
import os
import sys
import glob
import argparse
import time
import json
import cv2
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from watermark.crypto_vault import load_secrets
from watermark.zero_watermark import (
    phase1_ai_roi_isolation, register_master_key_v3, extract_key_v3, compute_nc
)
from watermark.tamper_seal import embed_tamper_signature, verify_tamper_signature
from watermark.metrics import compute_psnr, compute_ssim


# ==============================================================================
# BASELINE 1: Global DWT-DCT (Ablation — No YOLO ROI Masking)
# ==============================================================================
def eval_global_dwt_dct(orig_bgr, suspect_bgr, master_seed=42):
    """
    Classical Zero-Watermarking: Treats the entire image as background.
    Extracts features indiscriminately across moving cars and static buildings.
    """
    h, w = orig_bgr.shape[:2]
    dummy_mask = np.ones((h, w), dtype=np.uint8) * 255
    try:
        w_key_reg, p_anchors, _, _, _ = register_master_key_v3(orig_bgr, dummy_mask, master_seed=master_seed)
        w_key_susp = extract_key_v3(suspect_bgr, dummy_mask, p_anchors, w_key_reg, orig_bgr.shape)
        nc_score = compute_nc(w_key_reg, w_key_susp)
        bit_acc = float(np.mean(w_key_reg == w_key_susp)) * 100.0
        # If NC < 0.75, tampering/mismatch detected
        detected = (nc_score < config.NC_THRESHOLD)
        return {"nc": nc_score, "bit_acc": bit_acc, "detected": detected}
    except Exception:
        return {"nc": 0.0, "bit_acc": 50.0, "detected": True}


# ==============================================================================
# BASELINE 2: Classical Error Level Analysis (ELA)
# ==============================================================================
def eval_error_level_analysis(suspect_bgr, quality=95, ela_threshold=14.0):
    """
    Classical Forensic ELA: Re-compresses suspect at Q=95 and calculates error surface.
    AI inpainting re-synthesizes consistent pixel grids, rendering ELA blind.
    """
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
    ok, encoded = cv2.imencode(".jpg", suspect_bgr, encode_param)
    compressed = cv2.imdecode(encoded, cv2.IMREAD_COLOR)
    diff = cv2.absdiff(suspect_bgr, compressed).astype(np.float32)

    # Check for localized error spikes (> threshold)
    grid = 16
    h, w = diff.shape[:2]
    ch, cw = h // grid, w // grid
    max_block_diff = 0.0
    for r in range(grid):
        for c in range(grid):
            m = diff[r*ch:(r+1)*ch, c*cw:(c+1)*cw].mean()
            if m > max_block_diff:
                max_block_diff = m

    detected = bool(max_block_diff > ela_threshold)
    return {"max_diff": round(float(max_block_diff), 2), "detected": detected}


# ==============================================================================
# BASELINE 3: Rel-Zero Patch-Pair Invariance (Chen et al., 2026 concept)
# ==============================================================================
def eval_rel_zero_patch_pairs(orig_bgr, suspect_bgr, n_pairs=256, master_seed=42):
    """
    Rel-Zero Concept: Extracts relational invariant differences between pairs of
    random patches across the image without semantic foreground/background separation.
    """
    h, w = orig_bgr.shape[:2]
    patch_size = 16
    rng = np.random.default_rng(master_seed)
    coords_a = [(rng.integers(0, max(1, h - patch_size)), rng.integers(0, max(1, w - patch_size))) for _ in range(n_pairs)]
    coords_b = [(rng.integers(0, max(1, h - patch_size)), rng.integers(0, max(1, w - patch_size))) for _ in range(n_pairs)]

    gray_orig = cv2.cvtColor(orig_bgr, cv2.COLOR_BGR2GRAY).astype(np.float32)
    gray_susp = cv2.cvtColor(suspect_bgr, cv2.COLOR_BGR2GRAY).astype(np.float32)

    bits_orig, bits_susp = [], []
    for (r1, c1), (r2, c2) in zip(coords_a, coords_b):
        pA_o = gray_orig[r1:r1+patch_size, c1:c1+patch_size].mean()
        pB_o = gray_orig[r2:r2+patch_size, c2:c2+patch_size].mean()
        bits_orig.append(1 if pA_o > pB_o else 0)

        pA_s = gray_susp[r1:r1+patch_size, c1:c1+patch_size].mean()
        pB_s = gray_susp[r2:r2+patch_size, c2:c2+patch_size].mean()
        bits_susp.append(1 if pA_s > pB_s else 0)

    bits_orig = np.array(bits_orig, dtype=np.uint8)
    bits_susp = np.array(bits_susp, dtype=np.uint8)
    nc_score = compute_nc(bits_orig, bits_susp)
    bit_acc = float(np.mean(bits_orig == bits_susp)) * 100.0

    return {"nc": nc_score, "bit_acc": bit_acc, "detected": nc_score < config.NC_THRESHOLD}


# ==============================================================================
# PROPOSED FRAMEWORK: YOLO-Guided DWT-DCT + QIM Seal
# ==============================================================================
def eval_proposed_framework(orig_bgr, suspect_bgr, master_seed=42):
    _, _, m_buffer = phase1_ai_roi_isolation(orig_bgr)
    w_key_reg, p_anchors, _, _, _ = register_master_key_v3(orig_bgr, m_buffer, master_seed=master_seed)
    signed_img, tamper_hash = embed_tamper_signature(orig_bgr, master_seed=master_seed)

    w_key_susp = extract_key_v3(suspect_bgr, m_buffer, p_anchors, w_key_reg, orig_bgr.shape)
    nc_score = compute_nc(w_key_reg, w_key_susp)
    bit_acc = float(np.mean(w_key_reg == w_key_susp)) * 100.0

    seal = verify_tamper_signature(suspect_bgr, tamper_hash, orig_bgr.shape, master_seed=master_seed)
    detected = (not seal["seal_intact"]) or (nc_score < config.NC_THRESHOLD)

    return {"nc": nc_score, "bit_acc": bit_acc, "detected": detected}


# ==============================================================================
# BATCH BENCHMARK RUNNER
# ==============================================================================
def run_all_baselines(orig_dir, ai_dir, max_images=25):
    orig_files = sorted(glob.glob(os.path.join(orig_dir, "*.*")))
    orig_files = [f for f in orig_files if os.path.splitext(f)[1].lower() in (".png", ".jpg", ".jpeg")][:max_images]

    if not orig_files:
        print(f"❌ No images found in {orig_dir}")
        return

    print("=" * 90)
    print(f"🔬 RUNNING COMPARATIVE BASELINE EVALUATION ({len(orig_files)} SCENES)")
    print(f"   Clean Originals   : {orig_dir}")
    print(f"   AI-Tampered Feeds : {ai_dir}")
    print("=" * 90)

    data = {
        "global_dwt": {"nc": [], "acc": [], "detected": 0, "times": []},
        "ela":        {"detected": 0, "times": []},
        "rel_zero":   {"nc": [], "acc": [], "detected": 0, "times": []},
        "proposed":   {"nc": [], "acc": [], "detected": 0, "times": []},
    }

    valid_scenes = 0

    for idx, orig_path in enumerate(orig_files, 1):
        filename = os.path.basename(orig_path)
        stem = os.path.splitext(filename)[0]

        ai_path = os.path.join(ai_dir, filename)
        if not os.path.exists(ai_path):
            ai_matches = glob.glob(os.path.join(ai_dir, f"{stem}_*.*"))
            if ai_matches:
                ai_path = ai_matches[0]
            else:
                continue

        orig = cv2.imread(orig_path)
        susp = cv2.imread(ai_path)
        if orig is None or susp is None:
            continue

        valid_scenes += 1
        print(f"[{valid_scenes:02d}/{len(orig_files):02d}] Testing {stem} across all 4 methods ... ", end="", flush=True)

        # 1. Global DWT
        t0 = time.perf_counter()
        r1 = eval_global_dwt_dct(orig, susp)
        data["global_dwt"]["times"].append(time.perf_counter() - t0)
        data["global_dwt"]["nc"].append(r1["nc"])
        data["global_dwt"]["acc"].append(r1["bit_acc"])
        if r1["detected"]: data["global_dwt"]["detected"] += 1

        # 2. ELA
        t0 = time.perf_counter()
        r2 = eval_error_level_analysis(susp)
        data["ela"]["times"].append(time.perf_counter() - t0)
        if r2["detected"]: data["ela"]["detected"] += 1

        # 3. Rel-Zero
        t0 = time.perf_counter()
        r3 = eval_rel_zero_patch_pairs(orig, susp)
        data["rel_zero"]["times"].append(time.perf_counter() - t0)
        data["rel_zero"]["nc"].append(r3["nc"])
        data["rel_zero"]["acc"].append(r3["bit_acc"])
        if r3["detected"]: data["rel_zero"]["detected"] += 1

        # 4. Proposed (Ours)
        t0 = time.perf_counter()
        r4 = eval_proposed_framework(orig, susp)
        data["proposed"]["times"].append(time.perf_counter() - t0)
        data["proposed"]["nc"].append(r4["nc"])
        data["proposed"]["acc"].append(r4["bit_acc"])
        if r4["detected"]: data["proposed"]["detected"] += 1

        print("Done.")

    if valid_scenes == 0:
        print("❌ No matching image pairs found.")
        return

    # ==============================================================================
    # PRINT SUMMARY TABLE
    # ==============================================================================
    print("\n" + "=" * 95)
    print(f"  COMPARATIVE FORENSICS BENCHMARK SUMMARY (N={valid_scenes} Scenes)")
    print("=" * 95)
    print(f"{'Method / Baseline':<32} | {'Mean NC Score':<16} | {'Bit Accuracy':<14} | {'Tamper Detection Rate':<22} | {'Avg Latency':<12}")
    print("-" * 95)

    # 1. Global DWT
    g_nc = f"{np.mean(data['global_dwt']['nc']):.4f} ± {np.std(data['global_dwt']['nc']):.3f}"
    g_acc = f"{np.mean(data['global_dwt']['acc']):.2f}%"
    g_det = f"{(data['global_dwt']['detected'] / valid_scenes) * 100:.1f}% ({data['global_dwt']['detected']}/{valid_scenes})"
    g_time = f"{np.mean(data['global_dwt']['times']):.3f}s"
    print(f"{'1. Global DWT-DCT (No YOLO)':<32} | {g_nc:<16} | {g_acc:<14} | {g_det:<22} | {g_time:<12}")

    # 2. ELA
    ela_det = f"{(data['ela']['detected'] / valid_scenes) * 100:.1f}% ({data['ela']['detected']}/{valid_scenes})"
    ela_time = f"{np.mean(data['ela']['times']):.3f}s"
    print(f"{'2. Classical ELA (JPEG Q95)':<32} | {'N/A':<16} | {'N/A':<14} | {ela_det:<22} | {ela_time:<12}")

    # 3. Rel-Zero
    rz_nc = f"{np.mean(data['rel_zero']['nc']):.4f} ± {np.std(data['rel_zero']['nc']):.3f}"
    rz_acc = f"{np.mean(data['rel_zero']['acc']):.2f}%"
    rz_det = f"{(data['rel_zero']['detected'] / valid_scenes) * 100:.1f}% ({data['rel_zero']['detected']}/{valid_scenes})"
    rz_time = f"{np.mean(data['rel_zero']['times']):.3f}s"
    print(f"{'3. Rel-Zero (Patch-Pair)':<32} | {rz_nc:<16} | {rz_acc:<14} | {rz_det:<22} | {rz_time:<12}")

    # 4. Proposed (Ours)
    p_nc = f"{np.mean(data['proposed']['nc']):.4f} ± {np.std(data['proposed']['nc']):.3f}"
    p_acc = f"{np.mean(data['proposed']['acc']):.2f}%"
    p_det = f"{(data['proposed']['detected'] / valid_scenes) * 100:.1f}% ({data['proposed']['detected']}/{valid_scenes})"
    p_time = f"{np.mean(data['proposed']['times']):.3f}s"
    print(f"{'4. Proposed Framework (Ours)':<32} | {p_nc:<16} | {p_acc:<14} | {p_det:<22} | {p_time:<12}")
    print("=" * 95)

    # ==============================================================================
    # PRINT LATEX TABLE (Ready to paste into Overleaf)
    # ==============================================================================
    print("\n" + "=" * 95)
    print("  LATEX CODE FOR OVERLEAF (COMPARATIVE BASELINES)")
    print("=" * 95)
    print("\\begin{table}[h]")
    print("\\centering")
    print(f"\\caption{{Comparative Evaluation of Proposed Framework against Baselines ($N={valid_scenes}$).}}")
    print("\\begin{tabular}{l c c c c}")
    print("\\hline")
    print("Method & Mean NC Score & Bit Acc (\\%) & Detection Rate (\\%) & Latency (s) \\\\")
    print("\\hline")
    print(f"Global DWT-DCT (No YOLO) & {np.mean(data['global_dwt']['nc']):.3f} & {np.mean(data['global_dwt']['acc']):.1f}\\% & {(data['global_dwt']['detected'] / valid_scenes) * 100:.1f}\\% & {np.mean(data['global_dwt']['times']):.3f} \\\\")
    print(f"Classical ELA (JPEG Q95) & N/A & N/A & {(data['ela']['detected'] / valid_scenes) * 100:.1f}\\% & {np.mean(data['ela']['times']):.3f} \\\\")
    print(f"Rel-Zero (Patch-Pair) & {np.mean(data['rel_zero']['nc']):.3f} & {np.mean(data['rel_zero']['acc']):.1f}\\% & {(data['rel_zero']['detected'] / valid_scenes) * 100:.1f}\\% & {np.mean(data['rel_zero']['times']):.3f} \\\\")
    print(f"\\textbf{{Proposed Framework (Ours)}} & \\textbf{{{np.mean(data['proposed']['nc']):.3f}}} & \\textbf{{{np.mean(data['proposed']['acc']):.1f}\\%}} & \\textbf{{{(data['proposed']['detected'] / valid_scenes) * 100:.1f}\\%}} & {np.mean(data['proposed']['times']):.3f} \\\\")
    print("\\hline")
    print("\\end{tabular}")
    print("\\end{table}")
    print("=" * 95)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Baseline Comparison")
    parser.add_argument("--orig_dir", required=True, help="Folder of clean original images")
    parser.add_argument("--ai_dir", required=True, help="Folder of AI-tampered images")
    parser.add_argument("--max", type=int, default=25, help="Number of scenes to evaluate")
    parser.add_argument("--passphrase", "-p", default=None, help="Vault passphrase (omit to be prompted)")
    args = parser.parse_args()

    load_secrets(args.passphrase)
    run_all_baselines(args.orig_dir, args.ai_dir, max_images=args.max)
