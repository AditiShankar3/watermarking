This file is a merged representation of the entire codebase, combined into a single document by Repomix.

# File Summary

## Purpose
This file contains a packed representation of the entire repository's contents.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)

# Directory Structure
```
batch_jpeg_attack.py
run_profiler.py
```

# Files

## File: batch_jpeg_attack.py
```python
#!/usr/bin/env python3
"""
batch_jpeg_attack.py — generate JPEG-recompression attack samples from every
*_signed.png in an input directory, at several quality levels. Used to
evaluate false-positive rate under benign lossy compression.

Usage:
    python scripts/batch_jpeg_attack.py --input data/outputs/signed --output data/attack_samples
    python scripts/batch_jpeg_attack.py --input ... --output ... --qualities 95 85 70 50 30
"""
import argparse
import glob
import os
import sys

import cv2

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def batch_jpeg_compression_attack(input_dir, output_dir, qualities=(95, 85, 70, 50, 30)):
    os.makedirs(output_dir, exist_ok=True)
    png_files = glob.glob(os.path.join(input_dir, "*_signed.png"))
    if not png_files:
        png_files = glob.glob(os.path.join(input_dir, "*.png"))
    if not png_files:
        print(f"⚠️  No PNG files found in {input_dir}")
        return []

    results = []
    print(f"Found {len(png_files)} PNG file(s). Generating {len(qualities)} "
          f"quality variant(s) each ({len(png_files) * len(qualities)} total)...\n")
    for png_path in png_files:
        base_name = os.path.splitext(os.path.basename(png_path))[0]
        img = cv2.imread(png_path)
        if img is None:
            print(f"   skip (unreadable): {png_path}")
            continue
        for q in qualities:
            encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), q]
            ok, encoded = cv2.imencode(".jpg", img, encode_param)
            if not ok:
                continue
            compressed_img = cv2.imdecode(encoded, cv2.IMREAD_COLOR)
            out_name = f"{base_name}_jpegQ{q}.jpg"
            out_path = os.path.join(output_dir, out_name)
            cv2.imwrite(out_path, compressed_img, encode_param)
            size_kb = os.path.getsize(out_path) / 1024
            print(f"   {base_name}  Q={q:<3} -> {out_name}  ({size_kb:.1f} KB)")
            results.append({"source": png_path, "quality": q, "path": out_path})

    print(f"\nDone. {len(results)} attack sample(s) written to {output_dir}")
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", required=True, help="Directory containing *_signed.png files")
    ap.add_argument("--output", required=True, help="Directory to write JPEG attack samples")
    ap.add_argument("--qualities", type=int, nargs="+", default=[95, 85, 70, 50, 30])
    args = ap.parse_args()
    batch_jpeg_compression_attack(args.input, args.output, tuple(args.qualities))
```

## File: run_profiler.py
```python
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
```
