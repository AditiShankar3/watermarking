# 🔒 Zero-Watermark Traffic Image Authentication System

Forensic image authentication framework for protecting traffic surveillance images using **ROI-aware Zero Watermarking**, **Cryptographic Tamper Detection**, **Secure Evidence Storage**, and **Automated Recovery**.

---

## 📌 Overview

Traffic surveillance images are frequently used as legal evidence in accident investigations, law enforcement, and smart city monitoring. Traditional authentication methods fail to provide a complete forensic chain of custody, especially against modern AI-based image manipulation.

This project proposes an end-to-end forensic framework that combines computer vision, digital watermarking, cryptography, and secure storage to verify image authenticity while preserving image quality.

Unlike conventional watermarking systems, ownership information is generated without permanently modifying important image regions, making the framework suitable for forensic applications.

---

## ✨ Features

- 🚗 ROI detection using YOLOv8 Instance Segmentation
- 🛡️ ROI-aware Zero Watermark Generation
- 🌊 Three-Level HAAR Discrete Wavelet Transform (DWT)
- 📐 Block-wise Discrete Cosine Transform (DCT)
- 🔑 256-bit Zero Watermark Generation
- 🔍 SHA-256 based Fragile Tamper Seal
- 📍 Deterministic Scattered LSB Embedding
- 🔐 AES-256-GCM Encryption of Original Images
- ☁️ IPFS Backup Storage
- 📚 HMAC-Protected Registration Ledger
- 🚫 Blacklist-based Repeat Tampering Detection
- 📊 Tamper Localization
- 🔄 Automatic Original Image Recovery
- 🌐 FastAPI Backend
- ⚛️ React Frontend Dashboard

---

# System Architecture

```
                Registration Phase

 Original Image
        │
        ▼
 YOLOv8 ROI Segmentation
        │
        ▼
 Background Extraction
        │
        ▼
 3-Level HAAR DWT
        │
        ▼
 Block-wise DCT
        │
        ▼
 Zero Watermark Generation
        │
        ├─────────────► SHA-256 Tamper Seal
        │                     │
        │                     ▼
        │             Scattered LSB Embedding
        │
        ├─────────────► AES-256 Encryption
        │                     │
        │                     ▼
        │                IPFS Storage
        │
        ▼
 HMAC Signed Registration Ledger
        │
        ▼
 Distributed Signed Image


                Verification Phase

 Uploaded Image
        │
        ▼
 Blacklist Check
        │
        ▼
 SHA-256 Seal Verification
        │
        ▼
 Tamper Localization
        │
        ▼
 Zero Watermark Verification
        │
        ▼
 Ownership Decision
        │
        ├── Authentic
        │
        └── Tampered
                 │
                 ▼
        Recover Original Image
```

---

# Technology Stack

### Frontend

- React
- JavaScript
- HTML
- CSS

### Backend

- FastAPI
- Python

### Computer Vision

- YOLOv8
- OpenCV

### Image Processing

- PyWavelets
- NumPy
- Pillow

### Cryptography

- SHA-256
- AES-256-GCM
- HMAC-SHA256

### Storage

- MongoDB Atlas
- IPFS (Pinata)

---

# Project Workflow

## Registration

1. Upload original image.
2. Detect vehicles and pedestrians using YOLOv8.
3. Extract background regions.
4. Apply 3-level DWT.
5. Perform block-wise DCT.
6. Generate Zero Watermark.
7. Generate SHA-256 Tamper Seal.
8. Embed seal using scattered LSB.
9. Encrypt original image.
10. Upload encrypted image to IPFS.
11. Store registration metadata inside MongoDB.
12. Generate signed distributable image.

---

## Verification

1. Upload image.
2. Blacklist verification.
3. Verify SHA-256 Tamper Seal.
4. Detect manipulated regions.
5. Generate Zero Watermark.
6. Compare with registered watermark.
7. Calculate NC Score.
8. Decide Authentic / Tampered.
9. Recover original image if necessary.

---

# Folder Structure

```
watermark-ui/

├── backend/
│   ├── api.py
│   ├── pipeline_core.py
│   ├── image_vault/
│   ├── signed_images/
│   ├── outputs/
│   ├── recovery/
│   ├── registration_ledger.json
│   ├── gateway_results.json
│   ├── tamper_log.json
│   └── delivery_log.json
│
├── src/
│   ├── App.jsx
│   ├── api.js
│   └── components/
│
├── public/
│
├── package.json
├── requirements.txt
└── README.md
```

---

# Installation

## Backend

```bash
cd backend

python -m venv venv

source venv/bin/activate

pip install -r requirements.txt

uvicorn api:app --reload
```

Backend runs on

```
http://localhost:8000
```

---

## Frontend

```bash
npm install

npm run dev
```

Frontend runs on

```
http://localhost:5173
```

---

# Performance Highlights

- ROI-aware ownership verification
- Robust against JPEG compression
- Resistant to AI-based object removal
- Near-zero visual distortion
- Secure encrypted evidence preservation
- Automatic recovery of original images
- Multi-stage forensic verification pipeline

---

# Future Improvements

- Real-time CCTV video authentication
- Blockchain-based immutable ledger
- Multi-camera distributed verification
- Cloud-native deployment
- Edge AI optimization
- Mobile forensic verification application

---

# License

This project is intended for academic and research purposes.
