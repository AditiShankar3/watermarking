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
