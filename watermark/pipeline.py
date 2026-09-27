"""
pipeline.py — the two end-to-end flows: run_registration() (Person X) and
run_gateway() (the upload-time authenticity check). This is a straight port
of the notebook's Cell 7 / Cell 8 logic, with two changes:
  1. Images are loaded from a given file path instead of an interactive
     Colab/Jupyter upload widget (there's no notebook here to provide one).
  2. Registration diagnostics are one combined figure, skippable entirely
     via save_diagnostics=False (see visualizers.py).
Everything else — the check order, the block reasons, the recover-and-
deliver flow — is unchanged from the original.
"""
import os
import time
from datetime import datetime

import cv2
import imagehash

import config
from watermark.crypto_vault import encrypt_image, recover_original
from watermark.ledger import (
    get_image_hash, is_blacklisted, add_to_blacklist, write_block_log,
    load_all_ledger_entries, save_to_ledger, log_audit_event, _verify_record,
    _sign_record, LedgerTamperedError,
)
from watermark.metrics import PhaseTimer, compute_psnr, compute_ssim, compute_ber_from_accuracy, estimate_complexity
from watermark.tamper_seal import embed_tamper_signature, verify_tamper_signature, localise_tamper, classify_attack_type
from watermark.visualizers import show_registration_diagnostics, show_tamper_localisation
from watermark.zero_watermark import (
    phase1_ai_roi_isolation, register_master_key_v3, phase2_frequency_topology,
    extract_key_v3, verify_ownership, get_phash,
)


def load_image(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Not found: {path}")
    img = cv2.imread(path)
    if img is None:
        raise ValueError(f"Cannot decode: {path}")
    return img, os.path.basename(path)


def _append_result(record: dict):
    import json
    results = []
    if os.path.exists(config.RESULTS_FILE):
        with open(config.RESULTS_FILE, "r") as f:
            try:
                results = json.load(f)
            except Exception:
                results = []
    results.append(record)
    with open(config.RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=2)


# ── Post-delivery tamper lock (unchanged logic, ledger-file-backed) ─────────
def _log_delivery(img_bgr, filename):
    import json
    img_hash = get_image_hash(img_bgr)
    ph = str(get_phash(img_bgr))
    log = {}
    if os.path.exists(config.DELIVERY_LOG_FILE):
        with open(config.DELIVERY_LOG_FILE, "r") as f:
            log = json.load(f)
    record = {
        "filename": filename,
        "delivered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "img_hash": img_hash, "img_phash": ph, "status": "delivered_original",
    }
    record["hmac_sig"] = _sign_record(dict(record))
    log[img_hash] = record
    with open(config.DELIVERY_LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)
    print(f"   📋 Delivery logged [{img_hash[:8]}...]  (post-send tamper lock active)")


def _is_delivered_original(img_bgr):
    import json
    if not os.path.exists(config.DELIVERY_LOG_FILE):
        return False, None
    img_hash = get_image_hash(img_bgr)
    with open(config.DELIVERY_LOG_FILE, "r") as f:
        log = json.load(f)
    if img_hash in log:
        record = log[img_hash]
        try:
            _verify_record(record)
            return True, record
        except LedgerTamperedError:
            pass
    return False, None


def _is_tampered_delivery(img_bgr):
    import json
    if not os.path.exists(config.DELIVERY_LOG_FILE):
        return False, None, None
    img_hash = get_image_hash(img_bgr)
    suspect_ph = get_phash(img_bgr)
    with open(config.DELIVERY_LOG_FILE, "r") as f:
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
        if dist <= config.PHASH_MAX_DIST:
            try:
                _verify_record(record)
                return True, record, dist
            except LedgerTamperedError:
                continue
    return False, None, None


def deliver_recovered_original(entry, suspect_filename):
    print("\n🔓  Recovering original from encrypted vault ...")
    temp_path = os.path.join(config.RECOVERED_DIR, "_temp_recovered.png")
    recovered = recover_original(entry, save_path=temp_path)
    if recovered is None:
        print("   ⚠️  Vault decryption failed. Cannot recover.")
        return None

    print("   🔏  Embedding post-delivery tamper seal ...")
    delivered_signed, _ = embed_tamper_signature(recovered)
    base = os.path.splitext(suspect_filename)[0]
    delivery_name = f"recovered_{base}.png"
    delivery_path = os.path.join(config.RECOVERED_DIR, delivery_name)
    cv2.imwrite(delivery_path, delivered_signed)
    print(f"   ✅  Delivered sealed original -> {delivery_path}")

    _log_delivery(delivered_signed, delivery_name)
    log_audit_event("RECOVERY_DELIVERED", filename=suspect_filename,
                     img_bgr=delivered_signed, decision="DELIVERED",
                     details={"delivery_name": delivery_name})
    if os.path.exists(temp_path):
        os.remove(temp_path)
    return delivery_path


# ── ▶ REGISTRATION (Person X) ────────────────────────────────────────────────
def run_registration(image_path: str, save_diagnostics: bool = True, backup_ipfs: bool = True):
    img, filename = load_image(image_path)
    print(f"\n📸  Registering: {filename}")

    flagged, bl_record, match_type = is_blacklisted(img)
    if flagged:
        match_desc = ("exact pixel match" if match_type == "exact"
                      else f"perceptual match (pHash dist <= {config.PHASH_MAX_DIST})")
        print(f"\n⛔  REGISTRATION REFUSED - blacklisted ({match_desc}), "
              f"first blocked {bl_record['blocked_at']}: {bl_record['reason']}")
        log_audit_event("REGISTRATION_REFUSED_BLACKLISTED", filename=filename, img_bgr=img,
                         decision="REFUSED", details={"match_type": match_type, "reason": bl_record["reason"]})
        return None, None

    print("\nPhase 1 - YOLO ROI masking ...")
    img_rgb, M_binary, M_buffer = phase1_ai_roi_isolation(img)

    print("Phase 2-5 - Frequency topology + key generation ...")
    W_key, P_anchors_all, bg, LL3, dct_LL3 = register_master_key_v3(img, M_buffer)

    if save_diagnostics:
        import cv2 as _cv2
        gray_bg_for_plot = _cv2.cvtColor(
            __import__("watermark.zero_watermark", fromlist=["robust_prefilter_v2"]).robust_prefilter_v2(img),
            _cv2.COLOR_BGR2GRAY).astype("float64")
        show_registration_diagnostics(img_rgb, M_binary, M_buffer, gray_bg_for_plot,
                                       LL3, dct_LL3, P_anchors_all, W_key)

    print("\nEmbedding scattered tamper seal ...")
    img_signed, tamper_hash = embed_tamper_signature(img)

    print("Encrypting original -> vault ...")
    base_name = os.path.splitext(filename)[0]
    vault_name = encrypt_image(img, vault_name=base_name)

    img_hash = save_to_ledger(filename, img, M_buffer, W_key, P_anchors_all, tamper_hash, vault_name)

        # Inside run_registration() after encrypt_image:
    if backup_ipfs:
        try:
            from integrations.ipfs_storage import backup_to_ipfs_sync
        except ImportError:
            from ipfs_storage import backup_to_ipfs_sync

        vault_path = os.path.join(config.VAULT_DIR, vault_name + ".enc")
        backup_to_ipfs_sync(vault_path, img_hash)

    signed_name = base_name + "_signed" + os.path.splitext(filename)[1]
    signed_path = os.path.join(config.SIGNED_DIR, signed_name)
    cv2.imwrite(signed_path, img_signed)

    print(f"\n✅  REGISTRATION COMPLETE")
    print(f"   Signed copy : {signed_path}  <- send this to Person Y")
    print(f"   Vault file  : {config.VAULT_DIR}/{vault_name}.enc")
    print(f"   Key balance : {W_key.mean() * 100:.1f}% ones")

    log_audit_event("REGISTRATION", filename=filename, img_bgr=img, decision="REGISTERED",
                     details={"vault_name": vault_name, "tamper_hash": tamper_hash[:16]})
    return img, filename


# ── ▶ CONTENT AUTHENTICITY GATEWAY (verification) ────────────────────────────
def run_gateway(image_path: str, platform: str = "police_portal", auto_recover: bool = False):
    if platform not in config.PLATFORMS:
        raise ValueError(f"Choose from: {list(config.PLATFORMS.keys())}")
    cfg = config.PLATFORMS[platform]

    suspect_img, suspect_filename = load_image(image_path)
    print(f"\n⏳  Gateway checking: {suspect_filename}  [{cfg['icon']} {cfg['name']}]")
    pt = PhaseTimer()
    t_start = time.time()

    # Post-delivery checks
    is_clean, dl_record = _is_delivered_original(suspect_img)
    if is_clean:
        print(f"\n✅  ALLOW - verified clean delivered original ({dl_record['filename']})")
        log_audit_event("ALLOW_DELIVERED_ORIGINAL", filename=suspect_filename, img_bgr=suspect_img,
                         decision="ALLOW", details={"platform": platform, "delivered_as": dl_record["filename"]})
        return "ALLOW"

    is_tampered_delivery, td_record, ph_dist = _is_tampered_delivery(suspect_img)
    if is_tampered_delivery:
        print(f"\n⛔  BLOCK - edited version of a previously delivered original "
              f"(pHash dist={ph_dist}, orig={td_record['filename']})")
        add_to_blacklist(suspect_img, suspect_filename,
                          "Post-delivery tampering: edited version of delivered original")
        write_block_log(suspect_filename, suspect_img, ["Post-delivery tampering"], 0.0, "TAMPERED POST-DELIVERY")
        log_audit_event("BLOCK_POST_DELIVERY_TAMPER", filename=suspect_filename, img_bgr=suspect_img,
                         decision="BLOCK", details={"platform": platform, "phash_dist": ph_dist,
                                                     "original_delivery": td_record["filename"]})
        return "BLOCK"

    # Exact registered original?
    try:
        entries = load_all_ledger_entries()
        suspect_hash = get_image_hash(suspect_img)
        orig_match = next((e for e in entries if e["img_hash"] == suspect_hash), None)
    except FileNotFoundError as e:
        print(f"❌  {e}")
        return "ERROR"

    if orig_match is not None:
        print(f"\n✅  ALLOW - exact match to registered original "
              f"({orig_match['image_filename']}, registered {orig_match['timestamp']})")
        _append_result({
            "filename": suspect_filename, "image_shape": list(suspect_img.shape),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "decision": "ALLOW", "tamper_status": "INTACT", "seal_intact": True,
            "content_intact": True, "nc_score": 1.0, "bit_accuracy": 100.0, "ber": 0.0,
            "n_tampered_cells": 0, "resized": False, "block_reasons": [],
            "attack_type": "None (Untampered)", "recovery_attempted": False,
            "recovery_success": False, "recovery_time_s": None,
            "check_time_s": round(time.time() - t_start, 3),
        })
        log_audit_event("ALLOW_EXACT_MATCH", filename=suspect_filename, img_bgr=suspect_img,
                         decision="ALLOW", details={"platform": platform, "registered_as": orig_match["image_filename"]})
        return "ALLOW"

    # Blacklist
    flagged, bl_record, match_type = is_blacklisted(suspect_img)
    if flagged:
        print(f"\n⛔  BLOCK - permanently blacklisted ({match_type} match, "
              f"first blocked {bl_record['blocked_at']}): {bl_record['reason']}")
        _append_result({
            "filename": suspect_filename, "image_shape": list(suspect_img.shape),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "decision": "BLOCK", "tamper_status": "BLACKLISTED", "seal_intact": None,
            "content_intact": None, "nc_score": 0.0, "bit_accuracy": 0.0, "ber": 1.0,
            "n_tampered_cells": 0, "resized": False, "block_reasons": ["blacklisted"],
            "attack_type": "N/A (Pre-blacklisted)", "recovery_attempted": False,
            "recovery_success": False, "recovery_time_s": None,
            "check_time_s": round(time.time() - t_start, 3),
        })
        log_audit_event("BLOCK_BLACKLISTED", filename=suspect_filename, img_bgr=suspect_img,
                         decision="BLOCK", details={"platform": platform, "match_type": match_type,
                                                     "reason": bl_record["reason"]})
        return "BLOCK"

    # NC ownership scan over the full ledger
    best_nc, best_acc, best_entry = 0.0, 0.0, None
    second_best_nc = 0.0
    with pt.phase("nc_verification"):
        for entry in entries:
            eh, ew = entry["image_shape"][:2]
            img_r = cv2.resize(suspect_img, (ew, eh)) if suspect_img.shape[:2] != (eh, ew) else suspect_img
            key_ext = extract_key_v3(img_r, entry["M_buffer"], entry["P_anchors_all"],
                                      entry["W_key"], tuple(entry["image_shape"]))
            nc, acc, _ = verify_ownership(entry["W_key"], key_ext)
            if nc > best_nc:
                second_best_nc = best_nc
                best_nc, best_acc, best_entry = nc, acc, entry
            elif nc > second_best_nc:
                second_best_nc = nc

    if best_entry is None:
        print("❌  No matching registered image.")
        return "BLOCK"

    eh, ew = best_entry["image_shape"][:2]
    img_r = cv2.resize(suspect_img, (ew, eh)) if suspect_img.shape[:2] != (eh, ew) else suspect_img.copy()

    with pt.phase("tamper_seal_check"):
        tamper = verify_tamper_signature(img_r, best_entry["tamper_hash"], tuple(best_entry["image_shape"]))
        tamper_ok = tamper["seal_intact"]

    n_tampered, heatmap_path, recovered_orig = 0, None, None
    tamper_map, mad_grid = None, None
    if not tamper_ok:
        with pt.phase("localisation"):
            print("\n🔬  Running tamper localisation ...")
            recovered_orig = recover_original(best_entry)
            if recovered_orig is not None:
                tamper_map, mad_grid, cell_h, cell_w = localise_tamper(recovered_orig, suspect_img)
                n_tampered = int(tamper_map.sum())
                heatmap_path = show_tamper_localisation(
                    recovered_orig, suspect_img, tamper_map, mad_grid, cell_h, cell_w,
                    save_name=f"{os.path.splitext(suspect_filename)[0]}_heatmap.png")

    ownership_ok = best_nc >= cfg["nc_threshold"]
    block_reasons = []
    if not tamper_ok:
        block_reasons.append(f"Tamper seal broken - {tamper['detail']}")
    if not ownership_ok:
        block_reasons.append(f"NC score {best_nc:.4f} below threshold {cfg['nc_threshold']}")
    decision = "BLOCK" if block_reasons else "ALLOW"

    psnr_val, ssim_val = None, None
    if recovered_orig is not None:
        psnr_val = compute_psnr(recovered_orig, img_r)
        ssim_val = compute_ssim(recovered_orig, img_r)

    attack_label, attack_detail, _ = classify_attack_type(
        tamper, tamper_map, mad_grid, best_nc, cfg["nc_threshold"],
        second_best_nc=second_best_nc, psnr_val=psnr_val, ssim_val=ssim_val)

    ber_val = compute_ber_from_accuracy(best_acc)
    phase_times = pt.summary()
    complexity_info = estimate_complexity(phase_times, len(entries), suspect_img.shape)

    if decision == "BLOCK":
        add_to_blacklist(img_r, suspect_filename, block_reasons[0] if block_reasons else "Check failed")
        write_block_log(suspect_filename, img_r, block_reasons, best_nc, tamper["status"])

    log_audit_event(decision, filename=suspect_filename, img_bgr=img_r, decision=decision,
                     details={"platform": platform, "nc_score": round(float(best_nc), 4),
                              "bit_accuracy": round(float(best_acc), 2), "ber": ber_val,
                              "seal_intact": bool(tamper_ok), "block_reasons": block_reasons,
                              "attack_type": attack_label})

    verdict = "🚫 BLOCK" if decision == "BLOCK" else "✅ ALLOW"
    print(f"\n{verdict}  |  NC={best_nc:.4f} (threshold {cfg['nc_threshold']})  "
          f"|  seal_intact={tamper_ok}  |  attack_type={attack_label}")
    if heatmap_path:
        print(f"  heatmap: {heatmap_path}")
    if block_reasons:
        for i, r in enumerate(block_reasons, 1):
            print(f"  reason {i}: {r}")

    result_record = {
        "filename": suspect_filename, "image_shape": list(suspect_img.shape),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "decision": decision, "tamper_status": tamper["status"],
        "seal_intact": bool(tamper["seal_intact"]),
        "content_intact": bool(tamper["content_intact"]) if tamper.get("content_intact") is not None else None,
        "nc_score": round(float(best_nc), 4), "second_best_nc": round(float(second_best_nc), 4),
        "bit_accuracy": round(float(best_acc), 2), "ber": ber_val,
        "psnr_db": round(psnr_val, 2) if psnr_val is not None else None,
        "ssim": round(ssim_val, 4) if ssim_val is not None else None,
        "n_tampered_cells": int(n_tampered), "resized": bool(tamper.get("resized", False)),
        "block_reasons": block_reasons, "attack_type": attack_label, "attack_detail": attack_detail,
        "phase_times_s": phase_times, "recovery_attempted": False, "recovery_success": False,
        "recovery_time_s": None, "check_time_s": phase_times.get("total", 0),
        "computational_complexity": complexity_info,
    }

    if decision == "BLOCK":
        do_recover = auto_recover
        if not auto_recover:
            try:
                do_recover = input("  ▶ Recover and deliver original? [y/N]: ").strip().lower() == "y"
            except EOFError:
                do_recover = False
        result_record["recovery_attempted"] = do_recover
        if do_recover:
            t_rec = time.time()
            delivery_path = deliver_recovered_original(best_entry, suspect_filename)
            result_record["recovery_time_s"] = round(time.time() - t_rec, 3)
            result_record["recovery_success"] = delivery_path is not None
            if delivery_path:
                print(f"  ✅ recovered & delivered -> {delivery_path}")

    _append_result(result_record)
    return decision
