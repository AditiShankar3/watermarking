# Zero-Watermark Chain-of-Custody System for Traffic Surveillance Imagery

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![YOLOv8 Segmentation](https://img.shields.io/badge/YOLOv8-Segmentation-green.svg)](https://github.com/ultralytics/ultralytics)
[![AES-256-GCM](https://img.shields.io/badge/Security-AES--256--GCM-red.svg)](https://cryptography.io/)

A two-tier image-authentication and digital-forensics framework for traffic surveillance imagery. It combines a structural **zero-watermark** based on YOLO object segmentation and DWT-DCT background features with a **semi-fragile DCT-QIM tamper seal** designed to tolerate selected benign compression operations while remaining sensitive to image edits.

The system also includes an HMAC-authenticated ledger, an AES-256-GCM encrypted evidence vault, optional IPFS/Pinata backups, and a hash-chained forensic audit log.

> This repository implements a research prototype. Detection and robustness claims should be interpreted in the context of the datasets, attacks, and thresholds actually evaluated.

## Key Features

- **Semantic background isolation:** Uses YOLOv8n-seg to identify traffic-related objects and derive structural features from selected background regions.
- **Zero-watermarking:** Generates an ownership fingerprint from image-frequency features without modifying the original image for ownership proof.
- **Semi-fragile tamper seal:** Uses luminance-channel DCT and Quantization Index Modulation (QIM) to balance tolerance to selected benign transformations with sensitivity to edits.
- **Open-world verification:** Supports `ALLOW`, `BLOCK`, and `NOT_REGISTERED` outcomes based on the configured verification logic.
- **Tamper localization:** Includes Mean Absolute Difference (MAD) heatmap diagnostics.
- **Evidence protection:** Uses AES-256-GCM encryption and HMAC-authenticated ledger records.
- **Cloud integrations:** Supports Pinata/IPFS backup, Google Drive backup, and MongoDB Atlas synchronization.
- **Forensic auditing:** Maintains audit records intended to make record alteration detectable.
- **Resource profiling:** Measures CPU time and peak resident memory for registration workflows.

## Project Structure

The following layout is based on the repository's current `README.md`. Confirm it against the latest branch if files have changed since that README was committed.

```text
watermarking/
├── config.py
├── main.py
├── requirements.txt
├── .env.example
├── watermark/
│   ├── crypto_vault.py
│   ├── zero_watermark.py
│   ├── tamper_seal.py
│   ├── metrics.py
│   ├── ledger.py
│   ├── visualizers.py
│   └── pipeline.py
├── integrations/
│   ├── ipfs_storage.py
│   ├── google_drive_backup.py
│   └── mongo_sync.py
├── scripts/
│   ├── run_profiler.py
│   └── batch_jpeg_attack.py
└── data/   # Runtime data; gitignored
```

### Main Modules

| File | Responsibility |
|---|---|
| `config.py` | Tunable constants, thresholds, environment-loaded settings, and paths |
| `main.py` | CLI entry point for registration, verification, audit, and other supported commands |
| `watermark/crypto_vault.py` | Passphrase-protected secret storage and AES-256-GCM evidence vault |
| `watermark/zero_watermark.py` | YOLO ROI processing, DWT-DCT feature extraction, key generation/extraction, and NC scoring |
| `watermark/tamper_seal.py` | Semi-fragile DCT-QIM seal, MAD localization, and attack classification |
| `watermark/metrics.py` | PSNR, SSIM, BER, timing, complexity, and CPU/memory profiling |
| `watermark/ledger.py` | HMAC-authenticated ledger, blacklist handling, and forensic audit records |
| `watermark/visualizers.py` | Registration diagnostics and visualization of processing stages |
| `watermark/pipeline.py` | Registration and verification pipeline orchestration |
| `integrations/ipfs_storage.py` | Pinata/IPFS backup and CID ledger updates |
| `integrations/google_drive_backup.py` | Google Drive backup for supported records and results |
| `integrations/mongo_sync.py` | MongoDB Atlas synchronization |
| `scripts/run_profiler.py` | Standalone resource profiler |
| `scripts/batch_jpeg_attack.py` | Generates JPEG recompression attack samples |

## Requirements

- Python 3.10 or later
- Dependencies listed in `requirements.txt`
- Internet access on first use if YOLO model weights need to be downloaded
- Optional service credentials for integrations such as Pinata, Google Drive, and MongoDB Atlas

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/AditiShankar3/watermarking.git
cd watermarking
```

### 2. Create and activate a virtual environment

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

The first YOLO segmentation call may download `yolov8n-seg.pt` automatically if the weights are not already available.

### 4. Configure environment variables

Create a local `.env` file:

```bash
cp .env.example .env
```

Set only the variables required for the integrations you intend to use. These may include:

- `PINATA_JWT` — Pinata API token for IPFS uploads.
- `MONGO_URI` — MongoDB Atlas connection string.
- Google Drive configuration values used by the backup integration.
- Any configured local paths or runtime options.

**Security:** Never commit `.env`, access tokens, passphrases, encryption keys, HMAC secrets, or private runtime evidence to Git.

## Usage

Run `python3 main.py -h` to see the commands and options supported by the current code.

### 1. Register an image

```bash
python3 main.py register samples/original.jpg
```

Registration is intended to generate the image's structural fingerprint and tamper seal, protect the original in the encrypted vault, update the ledger, and upload encrypted evidence to IPFS when the relevant integration is configured.

### 2. Verify a suspect image

```bash
python3 main.py verify samples/suspect.jpg --platform police_portal
```

To test an image that has not been registered:

```bash
python3 main.py verify samples/unregistered.png
```

The verification pipeline evaluates the image against the registered evidence and configured decision thresholds. A result should be interpreted according to the policy and test conditions; it is not a guarantee of authenticity against every possible attack.

### 3. Inspect the audit trail

```bash
python3 main.py audit
```

### 4. Profile registration resources

```bash
python3 scripts/run_profiler.py --images samples/test_set/
```

### 5. Generate JPEG attack samples

The repository includes a JPEG recompression generator:

```bash
python3 main.py jpeg-attack -h
```

Check the help output for the exact required arguments and output options. The generator is documented as supporting quality levels such as `95`, `85`, `70`, `50`, and `30`.

### Other CLI integrations

The repository README documents additional commands for cloud backup and synchronization, including `backup-drive` and `sync-mongo`. Use `python3 main.py -h` for their exact arguments.

## Verification Decisions

The gateway is designed around three outcomes:

- **`ALLOW`** — the image meets the configured verification criteria.
- **`BLOCK`** — the image is registered or sufficiently correlated but the seal or other checks indicate a potential modification.
- **`NOT_REGISTERED`** — the image falls below the configured correlation floor and cannot be matched to registered evidence.

Thresholds and precedence must be checked in the implementation and calibrated using validation data. In particular, ensure that the conditions for `ALLOW` and `BLOCK` cannot produce ambiguous outcomes.

## Security and Evidence Handling

- Protect passphrases, encryption keys, HMAC secrets, and environment variables.
- Verify AES-GCM authentication tags before accepting decrypted evidence.
- Validate ledger authentication and audit-chain continuity during forensic review.
- Treat an IPFS CID as a content-addressing reference, not as proof of authenticity or confidentiality by itself.
- Restrict access to evidence recovery and record recovery operations in the audit trail.
- Keep runtime data, generated images, ledgers, and vault files out of version control unless there is a deliberate, safe reason to publish test fixtures.

## Known Issues and Future Work

The repository's existing documentation identifies the following limitations:

1. **Resize-induced NC drift:** Non-power-of-two resizing and aspect-ratio changes may cause anchor remapping drift in `extract_key_v3`.
2. **Blacklist administration:** The current blacklist workflow does not provide an administrative override through the documented interface.
3. **pHash lookup scalability:** Linear perceptual-hash scans may become expensive for large evidence collections; an index such as a BK-tree could improve near-duplicate lookup performance.

## Evaluation Notes

For research reporting, document the dataset, number of scenes, attack types, compression settings, thresholds, and hardware used. Report ownership verification and tamper detection separately, and include false-acceptance and false-rejection results where possible. Avoid generalizing a result beyond the test conditions under which it was measured.

## License

This project is licensed under the MIT License. See the [`LICENSE`](LICENSE) file for details.
