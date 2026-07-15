# REL-ZERO: Relational Zero-Watermarking for Traffic Camera Image Authentication

> YOLO-Guided ROI Segmentation • DWT-DCT Structural Fingerprinting • Scattered LSB Tamper Sealing

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)
[![YOLOv8](https://img.shields.io/badge/YOLOv8-Segmentation-orange)](https://github.com/ultralytics/ultralytics)
[![Jupyter](https://img.shields.io/badge/Notebook-Jupyter-F37626?logo=jupyter)](https://jupyter.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Research%20Prototype-yellow)]()

A forensic-grade, non-intrusive image authentication framework for traffic surveillance evidence. The system proves **ownership**, detects **tampering**, **localizes** manipulated regions, **classifies attacks**, and **recovers** the original image — all without modifying the visible content of the distributed image.

---

## Table of Contents

- [Overview](#overview)
- [Why Zero-Watermarking?](#why-zero-watermarking)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [How It Works](#how-it-works)
  - [Registration Phase](#registration-phase)
  - [Verification Phase](#verification-phase)
- [Tech Stack](#tech-stack)
- [Repository Structure](#repository-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Experimental Results](#experimental-results)
- [Security Analysis](#security-analysis)
- [Limitations](#limitations)
- [Roadmap / Future Work](#roadmap--future-work)
- [References](#references)
- [Authors](#authors)
- [License](#license)

---

## Overview

Traffic surveillance images are increasingly used as forensic and legal evidence, but their integrity is hard to guarantee once they leave the camera. Conventional approaches fall short:

| Technique | Limitation |
|---|---|
| Metadata | Trivially stripped or modified |
| Cryptographic hashing (SHA-256) | Breaks under harmless operations (recompression, resizing) |
| Traditional watermarking | Degrades image quality; forces a robustness vs. fidelity trade-off |
| AI forensic classifiers | Detect manipulation but can't prove ownership or recover originals |

**REL-ZERO** combines computer vision, frequency-domain feature extraction, and applied cryptography into a single end-to-end pipeline that authenticates traffic camera images without embedding the ownership signature into the pixel data itself.

## Why Zero-Watermarking?

Instead of embedding ownership data into the image (which risks visual degradation), the framework **derives** a 256-bit ownership signature from stable structural features of the image background. The original image remains pixel-for-pixel unchanged with respect to ownership data — the signature lives in the protected ledger, not in the file.

A separate, intentionally *fragile* SHA-256 tamper seal is embedded via LSB steganography purely to detect pixel-level edits — this is the only mechanism that touches pixel values, and it does so with zero perceptible distortion.

## Key Features

- 🚗 **YOLOv8-based ROI segmentation** (`yolov8n-seg.pt`) — isolates vehicles/pedestrians (ROI) from static background (Non-ROI)
- 🌊 **3-Level HAAR DWT + Block-wise DCT** — extracts a robust structural fingerprint from DC-coefficient energy, resilient to JPEG recompression and resizing
- 🔑 **256-bit Zero Watermark** — generated via anchor selection and replica-based majority voting; never embedded in the image
- 🔒 **Scattered SHA-256 tamper seal** — deterministically scattered, LSB-embedded fragile fingerprint for pixel-level tamper detection
- 🗺️ **MAD-based tamper localization** — 16×16 grid heatmap pinpointing manipulated regions (`*_ai_heatmap.png`, `*_cmp_heatmap.png`)
- 🧠 **Rule-based attack classification** — distinguishes JPEG recompression, AI object removal/regeneration, and heavy editing
- 🔐 **AES-256-GCM encrypted vault** — original evidence recoverable only after verified tampering
- 🧾 **HMAC-signed audit ledger** — tamper-evident registration records (`registration_ledger.json`)
- 🚫 **Dual-hash blacklist** — SHA-256 (exact) + perceptual hash (visually similar) duplicate/blocked-image detection (`tamper_blacklist.json`)
- 📜 **Forensic logging** — tamper events, gateway decisions, and image delivery are all independently logged

## System Architecture

The framework operates in two major phases:

```
                         ┌─────────────────────┐
                         │   Captured Image     │
                         └──────────┬───────────┘
                                    │
                 ┌──────────────────┴──────────────────┐
                 ▼                                      ▼
      ┌─────────────────────┐              ┌─────────────────────────┐
      │  REGISTRATION PHASE  │              │   (later) VERIFICATION   │
      │                       │              │          PHASE           │
      │  YOLOv8 ROI Segment.  │              │  Blacklist Check          │
      │  → Background Mask    │              │  → Ledger/HMAC Verify     │
      │  → 3-Level HAAR DWT   │              │  → Tamper Seal Extraction │
      │  → Block-wise DCT     │              │  → Zero Watermark Regen   │
      │  → Zero Watermark     │              │  → NC Score Computation   │
      │  → SHA-256 Tamper Seal│              │  → Tamper Localization    │
      │  → LSB Embedding      │              │  → Attack Classification  │
      │  → AES-256-GCM Vault  │              │  → Original Recovery      │
      │  → HMAC Ledger Entry  │              │  → Final Decision         │
      └───────────┬───────────┘              └────────────┬──────────────┘
                  ▼                                        ▼
         Signed Image (image_vault/)            Verified / Tampered / Rejected
```

## How It Works

### Registration Phase

Executed once, immediately after image capture in a trusted environment.

1. **Image Acquisition** — the raw image is assumed authentic at the point of capture.
2. **ROI Segmentation (YOLOv8 Nano)** — detects vehicles/pedestrians as the Region of Interest; everything else is Non-ROI (background). Diagnostic output: `reg_yolo.png`.
3. **Background Mask Generation** — a buffer mask is created via morphological erosion to avoid unstable object-boundary pixels.
4. **Frequency-Domain Transform** — background undergoes bilateral filtering + Gaussian blur, then a **3-level HAAR DWT**, then **block-wise 4×4 DCT** to extract DC-coefficient energy. Diagnostic output: `reg_frequency.png`.
5. **Anchor Selection & Majority Voting** — the brightest/darkest 15% of "safe" blocks are chosen deterministically (via `MASTER_SEED`); 5 independent replicas vote to finalize each bit. Diagnostic output: `reg_anchors.png`.
6. **Zero Watermark Generation** — DC coefficients are thresholded against the global median to produce a **256-bit binary ownership signature**, stored only in the ledger. Diagnostic output: `reg_key.png`.
7. **Tamper Seal Generation** — a SHA-256 hash of the original image is deterministically scattered across pixel coordinates and embedded via **LSB steganography**, producing the *Signed Image* (saved to `image_vault/*_signed.png` / `.jpg`).
8. **Secure Evidence Preservation** — the original image is encrypted with **AES-256-GCM** (key material in `aes.key.enc`) and stored in the local vault.
9. **HMAC-Protected Ledger** — all registration data (hashes, watermark, anchors, vault reference, timestamp) is signed with an HMAC key (`ledger.hmac_secret.enc`) and appended to `registration_ledger.json`.

### Verification Phase

Can be executed repeatedly, any time an image is uploaded to the authentication gateway.

1. **Blacklist Verification** — SHA-256 exact match, followed by perceptual-hash (pHash) Hamming-distance comparison against `tamper_blacklist.json`.
2. **Ledger Integrity Verification** — the stored HMAC signature is recomputed and validated before any other data is trusted.
3. **Tamper Seal Verification** — the embedded LSB fingerprint is extracted and compared against a freshly computed SHA-256 hash of the upload.
4. **Ownership Verification** — the zero watermark is **regenerated** from the uploaded image and compared to the stored watermark via **Normalized Correlation (NC)**, tolerant of benign transformations.
5. **Tamper Localization** — Mean Absolute Difference (MAD) is computed against the recovered original on a 16×16 grid, thresholded, and rendered as a heatmap (`*_ai_heatmap.png`, `*_cmp_heatmap.png`).
6. **Attack Classification** — a rule-based engine (SSIM, PSNR, MAD, tampered-cell count, seal status) labels the manipulation as JPEG recompression, object removal/AI regeneration, or heavy editing.
7. **Original Image Recovery** — if tampering is confirmed, the encrypted original is decrypted from the vault via AES-256-GCM and saved as `recovered_<id>_ai.png` / `recovered_<id>_cmp.png`.
8. **Final Decision** — the gateway logs its verdict (Verified / Tampered but Owned / Rejected) to `gateway_results.json` and `forensic_audit_log.json`.

## Tech Stack

| Layer | Technology |
|---|---|
| Object Segmentation | YOLOv8 Nano Segmentation (`yolov8n-seg.pt`, Ultralytics) |
| Frequency-Domain Processing | 3-Level HAAR DWT, Block-wise DCT |
| Cryptographic Hashing | SHA-256 |
| Symmetric Encryption | AES-256-GCM |
| Key Derivation | PBKDF2 |
| Message Authentication | HMAC-SHA256 |
| Steganography | Least Significant Bit (LSB) Embedding |
| Perceptual Similarity | Perceptual Hashing (pHash), Hamming Distance |
| Persistence | Local JSON ledger/log files (optionally MongoDB Atlas, per project documentation) |
| Development Environment | Jupyter Notebook (`watermark_final.ipynb`) |

> Update this table with any additional libraries (e.g., OpenCV, PyWavelets, `ultralytics`, `pycryptodome`, `imagehash`) once `requirements.txt` is finalized.

## Repository Structure

This reflects the current working project layout:

```
project_working/
├── watermark_final.ipynb          # Main notebook — full registration + verification pipeline
├── yolov8n-seg.pt                 # YOLOv8 Nano segmentation model weights
├── requirements.txt               # Python dependencies
│
├── registration_ledger.json       # HMAC-protected registration ledger
├── registration_ledger.json.zip   # Compressed backup of the ledger
├── tamper_blacklist.json          # SHA-256 + pHash blacklist store
├── tamper_log.json                # Tamper detection event log
├── forensic_audit_log.json        # Full forensic audit trail
├── gateway_results.json           # Verification gateway decisions/metrics
├── delivery_log.json              # Signed-image distribution log
│
├── master.seed.enc                # Encrypted MASTER_SEED (anchor selection + LSB scattering)
├── aes.key.enc                    # Encrypted AES-256-GCM key material
├── ledger.hmac_secret.enc         # Encrypted HMAC signing key
│
├── image_vault/                   # Signed images + tamper heatmaps per registered image
│   ├── <id>_signed.png / .jpg     # Distributable signed image (tamper seal embedded)
│   ├── <id>_ai_heatmap.png        # Localization heatmap — AI-regenerated attack test
│   └── <id>_cmp_heatmap.png       # Localization heatmap — compression/benign test
│
├── recovered_<id>_ai.png          # Original image recovered after AI-tamper detection
├── recovered_<id>_cmp.png         # Original image recovered after compression-tamper test
├── recovered_original.png         # Sample recovered original
│
├── reg_yolo.png                   # Diagnostic: YOLOv8 ROI/Non-ROI segmentation output
├── reg_frequency.png              # Diagnostic: DWT-DCT frequency-domain transform output
├── reg_anchors.png                # Diagnostic: anchor block selection visualization
├── reg_key.png                    # Diagnostic: generated 256-bit zero watermark
│
├── dataset_intern/                # Evaluation dataset
│   ├── <id>.png                   # Original test image
│   ├── <id>_ai.png                # AI-edited/regenerated variant (malicious test case)
│   └── compress/
│       ├── <id>.jpg                # Original (JPEG) test image
│       └── <id>_cmp.jpg            # Compressed variant (benign test case)
│
├── deleted_cmp_backup_<timestamp>/     # Rolling backup snapshot (compression test run)
└── deleted_ledger_backup_<timestamp>/  # Rolling backup snapshot (ledger)
```

> As the notebook is refactored into standalone modules (e.g., `registration/`, `verification/`, `ledger/`), update this tree to match.


**Recommended `.gitignore`:**

```gitignore
# Secrets / key material
*.enc

# Ledger & forensic data
registration_ledger.json
registration_ledger.json.zip
tamper_blacklist.json
tamper_log.json
forensic_audit_log.json
gateway_results.json
delivery_log.json

# Generated images / vault
image_vault/
recovered_*.png
recovered_original.png
reg_*.png

# Backups
deleted_cmp_backup_*/
deleted_ledger_backup_*/

# Dataset (track via Git LFS or external storage instead)
dataset_intern/

# Model weights (optional — large binary; consider Git LFS or a release asset)
*.pt

# Jupyter
.ipynb_checkpoints/

# Python
__pycache__/
*.pyc
venv/
.env
```

If you want reviewers to see *example* outputs, commit a small `samples/` folder with a handful of non-sensitive, synthetic, or already-public demo images instead of the full vault/dataset.

## Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/rel-zero.git
cd rel-zero

# Create a virtual environment
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Model Weights

The YOLOv8 Nano segmentation model (`yolov8n-seg.pt`) is required for ROI segmentation. If it isn't tracked in the repo (recommended — see `.gitignore` above), download it via Ultralytics:

```bash
pip install ultralytics
python -c "from ultralytics import YOLO; YOLO('yolov8n-seg.pt')"
```

### Environment Variables / Secrets

Do **not** hardcode secrets in the notebook. Create a `.env` file (excluded from git) with:

```env
MASTER_SEED=your_secret_seed
HMAC_SECRET_KEY=your_hmac_secret
VAULT_PASSPHRASE=your_vault_passphrase
NC_THRESHOLD=0.85
```

The notebook should load these via `python-dotenv` (or similar) rather than reading the `.enc` files directly in cleartext cells.

## Usage

The current implementation is driven from **`watermark_final.ipynb`**.

```bash
jupyter notebook watermark_final.ipynb
```

Inside the notebook:

1. **Registration** — run the registration cells on an image from `dataset_intern/` (or your own image) to produce:
   - A signed image in `image_vault/`
   - A new entry in `registration_ledger.json`
   - Diagnostic visualizations (`reg_yolo.png`, `reg_frequency.png`, `reg_anchors.png`, `reg_key.png`)
2. **Verification** — run the verification cells on a benign (`compress/*_cmp.jpg`) or malicious (`*_ai.png`) test variant to produce:
   - A tamper localization heatmap
   - An NC score and ownership decision
   - A recovered original (if tampering is confirmed)
   - Updated entries in `tamper_log.json`, `gateway_results.json`, and `forensic_audit_log.json`

> As the project matures, consider extracting the notebook into a CLI (`register.py` / `verify.py`) or a small API service for easier automation and testing.

## Experimental Results

Evaluated on a dataset of registered traffic surveillance images across three categories: **Genuine (untampered)**, **Compressed (benign)**, and **AI-Regenerated (malicious)**.

| Metric | Genuine | Compressed | AI-Regenerated |
|---|---|---|---|
| Dataset Size (N) | 92 | 62 | 179 |
| Mean NC Score | 0.9526 | 0.8951 | 0.8828 |
| Mean Bit Accuracy | 97.63% | 94.76% | 94.14% |
| Gateway Accuracy | 70.7% | 1.6% | 100.0% |

**Overall system performance:**

| Metric | Value |
|---|---|
| Detection Accuracy | 98.2% |
| Precision | 96.8% |
| Recall (TPR) | 100% |
| Specificity (TNR) | 96.1% |
| False Positive Rate | 3.9% |
| False Negative Rate | 0% |
| F1-Score | 0.984 |

**Original image recovery:**

| Metric | Value |
|---|---|
| Total Blocked Images | 267 |
| Recovery Attempted | 184 |
| Recovery Success Rate | 100% |
| Mean Recovery Time | 0.160 s |

## Security Analysis

The framework is evaluated against **Confidentiality, Integrity, Authentication, Ownership Verification, Availability, and Non-repudiation** goals, and further assessed using the **STRIDE** threat model (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

Key protections:
- AES-256-GCM + secure vault for confidentiality
- SHA-256 fragile seal + HMAC-protected ledger for integrity
- Zero watermark + NC scoring for ownership verification robust to benign edits

Known residual risks (see [Limitations](#limitations)) include shared-passphrase key derivation and the absence of gateway-level access control — both relevant if this repo is deployed rather than just used for research.

## Limitations

- Registration assumes a **trusted environment**; authenticity is not verified *before* enrollment.
- A single passphrase currently derives multiple secrets (AES key, HMAC key, `MASTER_SEED`) — weaker key separation than ideal.
- The fragile LSB tamper seal breaks under **any** modification, including benign JPEG recompression — by design, but can produce false "seal broken" flags even when ownership (NC) still verifies.
- No user authentication, role-based access control, or rate limiting on the verification gateway (current prototype).
- Blacklist lookup is a linear search — may not scale to very large datasets.
- Limited evaluation against adversarial attacks specifically targeting the YOLOv8 segmentation model.
- Designed for **still images**, not continuous video streams.
- Current persistence is local-file-based (`*.json`); MongoDB Atlas integration described in the project documentation is not yet reflected in this working directory.

## Roadmap / Future Work

- [ ] Refactor `watermark_final.ipynb` into modular `registration/` and `verification/` packages
- [ ] Pre-registration authenticity verification
- [ ] Role-based access control & multi-user authentication
- [ ] Faster blacklist search (locality-sensitive hashing / indexing)
- [ ] Extension to continuous video stream authentication
- [ ] Adversarially robust watermark generation
- [ ] Integration with **C2PA** (Coalition for Content Provenance and Authenticity) standards
- [ ] MongoDB Atlas backend for cross-session/cross-device ledger persistence

## References

1. Su, P.-C., Wang, H.-J. M., & Kuo, C.-C. J. (1999). *Digital Image Watermarking in Regions of Interest*. IS&T PICS Conference.
2. Gunjal, B. L., & Mali, S. N. (2012). *ROI Based Embedded Watermarking of Medical Images for Secured Communication in Telemedicine*. WASET IJCIE, 6(8).
3. Jamali, M., Samavi, S., Karimi, N., Soroushmehr, S. M. R., Ward, K., & Najarian, K. (2016). *Robust Watermarking in Non-ROI of Medical Images Based on DCT-DWT*. IEEE.
4. Li, Y., & Li, J. (2014). *Robust Volume Data Watermarking Based on Perceptual Hashing*. Computer Modelling & New Technologies, 18(11).
5. Karsh, R. K., Laskar, R. H., & Aditi. (2017). *Robust Image Hashing through DWT-SVD and Spectral Residual Method*. EURASIP JIVP, 2017(31).
6. Singh, P., & Chadha, R. S. (2013). *A Survey of Digital Watermarking Techniques, Applications and Attacks*. IJEIT, 2(9).
7. Lee, J. C. *Analysis of Attacks on Common Watermarking Techniques*. IEEE Student Paper, UBC.
8. Chen, P., Liu, Y., Gu, X., Chen, X., Liu, W., & Wang, W. (2026). *Rel-Zero: Harnessing Patch-Pair Invariance for Robust Zero-Watermarking Against AI Editing*. CVPR 2026.

## Authors

- **Aditi Shankar**
- **Hamsa B K**

Department of Computer Science and Engineering, PES University, Bengaluru, India

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

> If you'd rather use a different license (e.g., academic-only, GPL), update this section and the badge at the top accordingly.

---

<p align="center">Built for forensic-grade image authentication in smart-city traffic surveillance systems.</p>
