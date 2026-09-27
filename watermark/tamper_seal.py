"""
tamper_seal.py — the fragile half of the two-tier design: a SHA-256 hash of
the pixel content, embedded 1 bit per scattered pixel (blue-channel LSB),
at positions only derivable from the secret MASTER_SEED. Anyone without the
seed can't locate the seal to selectively preserve it during an edit.
"""
import hashlib
import hmac as hmac_lib

import cv2
import numpy as np

import config
from watermark.crypto_vault import get_master_seed


# ── Scattered LSB seal ────────────────────────────────────────────────────────
def _get_lsb_positions(img_bgr, n_bits, master_seed=None):
    """Deterministic (same seed -> same positions), scattered across the
    whole image — not fixed top-left, so an attacker can't crop it out
    without knowing the seed."""
    if master_seed is None:
        master_seed = get_master_seed()
    h, w = img_bgr.shape[:2]
    total_px = h * w
    rng = np.random.default_rng(
        int(hashlib.sha256(f"lsb_positions:{master_seed}".encode()).hexdigest(), 16) % (2 ** 31)
    )
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
    return "".join(
        format((bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3], "x")
        for i in range(0, len(bits), 4)
    )


def embed_tamper_signature(img_bgr, master_seed=None):
    """SHA-256 of pixels -> embed at MASTER_SEED-scattered positions.
    Returns (signed_image, tamper_hash)."""
    h = hashlib.sha256(img_bgr.tobytes()).hexdigest()
    signed = _embed_lsb(img_bgr, _hash_to_bits(h), master_seed)
    return signed, h


def verify_tamper_signature(suspect_bgr, registered_hash, original_shape, master_seed=None):
    """Resolution-aware: a resized copy will always fail a raw pixel-hash
    check, so resize is reported separately from genuine tampering rather
    than conflated with it."""
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
            status = "UNTAMPERED (resized copy)"
            detail = f"Resolution changed ({susp_w}x{susp_h} vs {orig_w}x{orig_h}) but LSB seal intact."
        else:
            status = "TAMPERED - seal destroyed (resized)"
            detail = "Resolution changed AND seal overwritten. Likely re-encoded after editing."
        return {"status": status, "detail": detail,
                "content_intact": False, "seal_intact": seal_intact, "resized": True}

    if content_intact:
        status, detail = "UNTAMPERED", "Pixel content matches registered original exactly."
    elif seal_intact:
        status, detail = "TAMPERED - seal survived", "Pixel content modified but LSB seal still readable."
    else:
        status, detail = "TAMPERED - seal destroyed", "Pixel content modified AND LSB seal overwritten."
    return {"status": status, "detail": detail,
            "content_intact": content_intact, "seal_intact": seal_intact, "resized": False}


# ── MAD-grid tamper localisation ─────────────────────────────────────────────
def localise_tamper(original_bgr, suspect_bgr, grid=config.TAMPER_BLOCKS,
                     threshold_pct=15, abs_floor=config.MAD_ABS_FLOOR):
    """16x16 mean-absolute-difference grid. A cell is flagged only if its MAD
    is BOTH in the top threshold_pct% AND above abs_floor — the absolute
    floor keeps clean images from flagging spurious cells just because
    *something* has to be the top percentile."""
    oh, ow = original_bgr.shape[:2]
    susp_r = cv2.resize(suspect_bgr, (ow, oh)) if suspect_bgr.shape[:2] != (oh, ow) else suspect_bgr.copy()
    diff = np.abs(original_bgr.astype(np.float32) - susp_r.astype(np.float32)).mean(axis=2)
    cell_h, cell_w = oh // grid, ow // grid
    mad_grid = np.array(
        [[diff[gr * cell_h:(gr + 1) * cell_h, gc * cell_w:(gc + 1) * cell_w].mean()
          for gc in range(grid)] for gr in range(grid)],
        dtype=np.float32)
    pct_cutoff = np.percentile(mad_grid, 100 - threshold_pct)
    tamper_map = (mad_grid >= pct_cutoff) & (mad_grid >= abs_floor)
    return tamper_map, mad_grid, cell_h, cell_w


# ── Heuristic attack-type classifier ─────────────────────────────────────────
# CALIBRATION NOTE: the thresholds below were anchored on a small labeled
# sample (documented in the original notebook as exactly two examples).
# Treat them as a reasonable starting boundary, not validated ground truth —
# re-check and tighten as you collect more labeled attack samples, ideally
# including images that were never registered at all (see README).
def classify_attack_type(tamper, tamper_map, mad_grid, best_nc, nc_threshold,
                          second_best_nc=None, psnr_val=None, ssim_val=None,
                          collusion_margin=0.05,
                          ssim_compression_floor=0.90,
                          ssim_ai_ceiling=0.85,
                          psnr_ai_ceiling=28.0,
                          mad_quant_ceiling=12.0,
                          mad_splice_floor=20.0):
    """Returns (attack_label, attack_detail, confidence)."""
    resized = tamper.get("resized", False)
    seal_intact = tamper.get("seal_intact", False)

    if resized and seal_intact:
        return ("None (Benign Transformation)",
                "Resolution changed but LSB seal intact - legitimate resize, no attack.",
                "heuristic")
    if (not resized) and tamper.get("content_intact", False):
        return ("None (Untampered)", "Exact pixel match to registered original.", "heuristic")

    if tamper_map is None or mad_grid is None:
        return ("Unclassified Tampering",
                "Seal broken but tamper-map unavailable for finer classification.",
                "heuristic")

    total_cells = tamper_map.size
    n_tampered = int(tamper_map.sum())
    tamper_pct = (n_tampered / total_cells) * 100
    flagged_vals = mad_grid[tamper_map] if n_tampered > 0 else np.array([0.0])
    mean_mad_flag = float(flagged_vals.mean())

    if resized and not seal_intact:
        return ("Resize + Re-encoding Attack",
                f"Resolution changed AND seal destroyed - image was resized "
                f"and/or resaved after editing ({tamper.get('detail', '')}).",
                "heuristic")

    if (second_best_nc is not None and (best_nc - second_best_nc) < collusion_margin
            and best_nc < nc_threshold + 0.10):
        return ("Possible Collusion Attack",
                f"Structural fingerprint sits nearly equidistant between two "
                f"registered originals (NC {best_nc:.4f} vs {second_best_nc:.4f}).",
                "heuristic")

    if ssim_val is not None and psnr_val is not None:
        if ssim_val < ssim_ai_ceiling or psnr_val < psnr_ai_ceiling:
            return ("AI Regeneration / Pixel-Laundering Attack",
                    f"Global fidelity collapsed (SSIM={ssim_val:.3f}, PSNR={psnr_val:.2f} dB) "
                    f"relative to the recovered original.",
                    "heuristic")
        if ssim_val >= ssim_compression_floor and mean_mad_flag < mad_quant_ceiling:
            return ("JPEG Recompression / Quantization Attack",
                    f"Global structure preserved (SSIM={ssim_val:.3f}, PSNR={psnr_val:.2f} dB) "
                    f"with only low-magnitude flagged cells (mean MAD={mean_mad_flag:.1f}).",
                    "heuristic")

    if tamper_pct <= 20 and mean_mad_flag >= mad_splice_floor:
        return ("Localized Splicing / Object Insertion-Removal",
                f"Tampering concentrated in {tamper_pct:.1f}% of the grid with "
                f"high contrast (mean flagged MAD={mean_mad_flag:.1f}).",
                "heuristic")

    return ("Unclassified Tampering",
            f"Seal broken, {tamper_pct:.1f}% of grid flagged (mean flagged MAD={mean_mad_flag:.1f}"
            + (f", SSIM={ssim_val:.3f}, PSNR={psnr_val:.2f} dB" if ssim_val is not None else "")
            + ") - pattern doesn't cleanly match a known category; needs manual review.",
            "heuristic")
