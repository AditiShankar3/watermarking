"""
metrics.py — PSNR/SSIM/BER quality metrics, per-phase timing, empirical
complexity estimation, AND per-image CPU-time / peak-memory profiling for
registration (the resource-constrained-device numbers).
"""
import gc
import os
import threading
import time

import cv2
import numpy as np
import psutil
from skimage.metrics import structural_similarity as _ssim


# ── Quality metrics ───────────────────────────────────────────────────────────
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


# ── Per-phase wall-clock timing ──────────────────────────────────────────────
class PhaseTimer:
    def __init__(self):
        self.times = {}
        self._t0_total = time.time()

    class _Ctx:
        def __init__(self, outer, name):
            self.outer, self.name = outer, name

        def __enter__(self):
            self._t0 = time.time()
            return self

        def __exit__(self, *exc):
            self.outer.times[self.name] = round(time.time() - self._t0, 4)

    def phase(self, name):
        return self._Ctx(self, name)

    def summary(self):
        self.times["total"] = round(time.time() - self._t0_total, 4)
        return dict(self.times)


def estimate_complexity(phase_times: dict, n_entries: int, image_shape: tuple):
    """Empirical scale-factor logging so complexity claims can be verified
    against real runs rather than asserted from Big-O alone."""
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
        "complexity_notes": {
            "nc_verification": "O(n_entries * H * W) - linear scan over ledger; each "
                                "comparison re-runs DWT+DCT on the full image. See "
                                "README for a pHash-prefiltering fix.",
            "tamper_seal_check": "O(k) - k = fingerprint bit length (fixed, 256), "
                                  "independent of image size",
            "localisation": "O(H * W) - pixel-wise MAD over the full image, "
                             "reduced into a fixed 16x16 grid",
        },
    }


# ── CPU time + peak-memory profiling (registration only) ────────────────────
# Verification happens server-side and isn't the bottleneck you're optimizing
# for; registration is what would run on a resource-constrained edge device,
# so that's what this profiles.
_PROC = psutil.Process(os.getpid())


class PeakMemorySampler:
    """Background thread polls RSS every `interval` seconds and tracks the
    peak reached DURING this `with` block. `resource.ru_maxrss` is a
    process-lifetime high-water mark that never resets, so it would
    under-report every call after the first large one — this samples fresh
    per call instead."""

    def __init__(self, interval=0.02):
        self.interval = interval
        self._stop = threading.Event()
        self.peak_rss = 0
        self.baseline_rss = 0
        self._thread = None

    def _run(self):
        while not self._stop.is_set():
            rss = _PROC.memory_info().rss
            if rss > self.peak_rss:
                self.peak_rss = rss
            time.sleep(self.interval)

    def __enter__(self):
        gc.collect()
        self.baseline_rss = _PROC.memory_info().rss
        self.peak_rss = self.baseline_rss
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()
        rss = _PROC.memory_info().rss
        if rss > self.peak_rss:
            self.peak_rss = rss

    @property
    def peak_mb(self):
        return self.peak_rss / (1024 ** 2)

    @property
    def delta_mb(self):
        return (self.peak_rss - self.baseline_rss) / (1024 ** 2)


def profile_one_registration(img_bgr, master_seed=None) -> dict:
    """Runs ONLY the core algorithmic work of registration (YOLO ROI +
    DWT/DCT key generation + LSB seal + PNG encode) — deliberately excludes
    matplotlib diagnostics and any network call (IPFS/Drive/Mongo), since
    neither reflects what an edge deployment would actually pay for.
    """
    from watermark.zero_watermark import phase1_ai_roi_isolation, register_master_key_v3
    from watermark.tamper_seal import embed_tamper_signature

    gc.collect()
    cpu_before = _PROC.cpu_times()
    t0 = time.perf_counter()

    with PeakMemorySampler(interval=0.02) as sampler:
        _, M_binary, M_buffer = phase1_ai_roi_isolation(img_bgr)
        W_key, P_anchors_all, bg, LL3, dct_LL3 = register_master_key_v3(
            img_bgr, M_buffer, master_seed=master_seed)
        _, tamper_hash = embed_tamper_signature(img_bgr, master_seed=master_seed)
        ok, buf = cv2.imencode(".png", img_bgr)

    wall_s = time.perf_counter() - t0
    cpu_after = _PROC.cpu_times()
    cpu_s = (cpu_after.user - cpu_before.user) + (cpu_after.system - cpu_before.system)

    return {
        "wall_time_s": round(wall_s, 4),
        "cpu_time_s": round(cpu_s, 4),
        "cpu_utilization_pct": round(100 * cpu_s / wall_s, 1) if wall_s > 0 else None,
        "peak_rss_mb": round(sampler.peak_mb, 2),
        "delta_rss_mb": round(sampler.delta_mb, 2),
        "w_key_ones_pct": round(float(W_key.mean()) * 100, 2),
        "tamper_hash": tamper_hash[:16] + "...",
    }
