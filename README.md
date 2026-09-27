
# Zero-Watermark Chain-of-Custody System

A two-tier, compression-robust image authentication and forensics framework: a structural "zero"-watermark (YOLO ROI segmentation + 3-level DWT/DCT background fingerprint, survives deepfakes and severe compression) composed with a semi-fragile DCT-QIM tamper seal (tolerates benign lossy compression, catches genuine edits), backed by an HMAC-signed ledger, decentralized IPFS evidence vault, and a hash-chained forensic audit log.

This repository is a modular, production-ready implementation of the research prototype — organized into clean, reusable modules runnable from the CLI or importable as an API, with credentials secured via `.env`.

## Setup

```bash
python3 -m venv .venv

source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env             # Fill in Pinata JWT, Mongo URI, and Google Drive configs
```

The first YOLO segmentation call automatically downloads `yolov8n-seg.pt` — no manual setup needed.

## Quick Start

```bash
# Register an original image (automatically embeds the semi-fragile seal,
# encrypts the original in the AES vault, and uploads to Pinata IPFS)
python3 main.py register samples/original.jpg

# Verify a suspect image against the registered ledger (3-way open-world check)
python3 main.py verify samples/suspect.jpg --platform police_portal

# Verify an unregistered image (cleanly rejected with no false accusations)
python3 main.py verify samples/unregistered.png

# View the hash-chained, tamper-evident forensic audit trail
python3 main.py audit

# Profile CPU time + peak RAM for registration across a folder of images
# (Profiles edge-device resource footprint, excluding network/GUI latency)
python3 scripts/run_profiler.py --images samples/test_set/
```

Run `python3 main.py -h` for the full command list (also: `jpeg-attack`, `backup-drive`, `sync-mongo`).

## Project Layout

```text
config.py                    All tunable constants, thresholds + env-loaded secrets/paths

main.py                      Streamlined CLI entrypoint (register, verify, audit)

watermark/

  crypto_vault.py             Passphrase-protected secret vault + AES-256-GCM image vault

  zero_watermark.py           YOLO ROI isolation, DWT/DCT key generation & extraction, NC scoring

  tamper_seal.py              Semi-fragile DCT-QIM seal, MAD localisation, attack-type classifier

  metrics.py                  PSNR/SSIM/BER, phase timing, complexity estimate, CPU/memory profiler

  ledger.py                   HMAC-signed ledger, dual-hash blacklist, forensic audit log

  visualizers.py              Combined diagnostics figure (ROI mask, DWT-DCT, anchor map, binary key)

  pipeline.py                 run_registration() and run_gateway() — the two end-to-end flows

integrations/

  ipfs_storage.py             Pinata/IPFS backup & automated CID ledger patching

  google_drive_backup.py      Google Drive backup for ledgers, logs, and gateway results

  mongo_sync.py               MongoDB Atlas cloud sync with Base64 mask compression

scripts/

  run_profiler.py             CPU/memory profiler as a standalone script

  batch_jpeg_attack.py        JPEG-recompression attack-sample generator across Q=[95, 85, 70, 50, 30]

data/                         Runtime data (gitignored): ledger, vault, logs, and outputs/
```

## What Changed vs. the Notebook (and Why)

- **Semi-Fragile DCT-QIM Seal:** Replaced the hyper-fragile spatial LSB seal with Quantization Index Modulation in mid-frequency DCT blocks. Survives benign lossy JPEG compression (`Q≥65`) while preserving sensitivity to vehicle deletion and AI inpainting.

- **3-Way Open-World Decision Logic:** Added an explicit correlation floor (`NC<0.50→NOT_REGISTERED`). Unregistered images are cleanly rejected without false accusations or spurious recovery attempts.

- **Automated IPFS Cloud Vault:** Registration seamlessly encrypts raw evidence via AES-256-GCM and backs it up to Pinata IPFS, immediately patching the CID into the HMAC-signed ledger.

- **Secrets moved to `.env`:** `MONGO_URI`, `PINATA_JWT`, Google Drive folder IDs, and local paths are read from environment variables only.

- **All runtime data isolated under `data/`:** Ledgers, vaults, audit logs, and generated heatmaps live in one gitignored directory with clear output subfolders.

- **One combined diagnostics figure:** `visualizers.py` renders all registration stages into a single diagnostic visual, skippable (`--no-diagnostics`) during batch evaluation.

- **Explicit secret management:** `crypto_vault.load_secrets()` is invoked deliberately at runtime; importing modules never prompts for passphrases.

- **Hardware resource profiling added:** `scripts/run_profiler.py` and `watermark/metrics.py` measure steady-state CPU time and peak RSS memory, providing real metrics for edge/IoT camera deployments.

## Known Issues & Future Scope

1. **Resize-induced NC drift on non-power-of-two scaling:** `extract_key_v3`'s anchor remap uses an approximation of the registered LL3 shape, which can drift under non-standard aspect ratio alterations.

2. **Permanent blacklist without administrative override:** A blacklisted image currently cannot be unlocked without modifying `tamper_blacklist.json`.

3. **pHash lookups scale linearly:** At large database scale (`N>10,000`), linear pHash scans should be transitioned to a BK-tree index over Hamming space for `O(log N)` near-duplicate candidate retrieval.