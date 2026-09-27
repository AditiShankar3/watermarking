#!/usr/bin/env python3
"""
run_profiler.py — measures per-image CPU time and peak memory for
REGISTRATION ONLY (verification runs server-side and isn't the bottleneck
for a resource-constrained device, so it isn't profiled here).

Deliberately excludes matplotlib diagnostics and any network call (IPFS/
Drive/Mongo) from the measured window — neither reflects what an edge
device would actually pay per image; see watermark/metrics.py.

Usage:
    python scripts/run_profiler.py --images path/to/test_images_folder
    python scripts/run_profiler.py --images ... --passphrase mypassphrase --out my_profile.json

If your target device is CPU-only, make sure YOLO_DEVICE=cpu in your .env
(the default) — profiling on a GPU runtime will under-report the CPU/RAM
cost a CPU-only edge device would actually see.
"""
import argparse
import glob
import json
import os
import statistics as stats
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cv2  # noqa: E402

import config  # noqa: E402
from watermark.crypto_vault import load_secrets  # noqa: E402
from watermark.metrics import profile_one_registration  # noqa: E402
from watermark.zero_watermark import get_yolo  # noqa: E402


def profile_directory(image_dir, out_json, passphrase=None):
    paths = [p for p in sorted(glob.glob(os.path.join(image_dir, "*")))
              if os.path.splitext(p)[1].lower() in (".png", ".jpg", ".jpeg")]
    if not paths:
        print(f"No images found in {image_dir}")
        return []

    load_secrets(passphrase)

    print("Warming YOLO model (excluded from per-image measurements)...")
    t0 = time.perf_counter()
    get_yolo()
    warmup_s = time.perf_counter() - t0
    print(f"   Model warm-up: {warmup_s:.2f}s (one-time, reported separately)\n")

    rows = []
    for i, p in enumerate(paths, 1):
        img = cv2.imread(p)
        if img is None:
            print(f"[{i}/{len(paths)}] {os.path.basename(p)} - unreadable, skipping")
            continue
        print(f"[{i}/{len(paths)}] {os.path.basename(p)} ... ", end="", flush=True)
        row = profile_one_registration(img)
        row["filename"] = os.path.basename(p)
        row["shape"] = list(img.shape)
        rows.append(row)
        print(f"wall={row['wall_time_s']}s  cpu={row['cpu_time_s']}s  peakRSS={row['peak_rss_mb']}MB")

    with open(out_json, "w") as f:
        json.dump({"yolo_warmup_s": round(warmup_s, 3), "images": rows}, f, indent=2)

    def summarize(key):
        vals = [r[key] for r in rows]
        return dict(mean=round(stats.mean(vals), 3), median=round(stats.median(vals), 3),
                    stdev=round(stats.stdev(vals), 3) if len(vals) > 1 else 0.0,
                    min=round(min(vals), 3), max=round(max(vals), 3))

    print("\n" + "=" * 60)
    print("  RESOURCE PROFILE SUMMARY (core registration pipeline only)")
    print("=" * 60)
    print(f"  N images              : {len(rows)}")
    print(f"  One-time YOLO warm-up  : {warmup_s:.2f}s (not counted per-image)")
    for key, label in [("wall_time_s", "Wall time (s)"), ("cpu_time_s", "CPU time (s)"),
                        ("peak_rss_mb", "Peak RSS (MB)"), ("delta_rss_mb", "Delta RSS over baseline (MB)")]:
        s = summarize(key)
        print(f"  {label:<28}: mean={s['mean']}  median={s['median']}  "
              f"stdev={s['stdev']}  min={s['min']}  max={s['max']}")
    print("=" * 60)
    print(f"  Full per-image data -> {out_json}")
    return rows


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--images", required=True, help="Directory of test images")
    ap.add_argument("--out", default=os.path.join(config.DATA_DIR, "resource_profile_registration.json"))
    ap.add_argument("--passphrase", default=None, help="Vault passphrase (omit to be prompted)")
    args = ap.parse_args()
    profile_directory(args.images, args.out, args.passphrase)
