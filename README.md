# Zero-Watermark Chain-of-Custody System

A two-tier image authentication system: a structural "zero"-watermark
(YOLO ROI + DWT/DCT fingerprint, survives benign compression) composed with
a fragile LSB tamper seal (catches genuine edits), backed by an HMAC-signed
ledger and a hash-chained forensic audit log.

This is a straight port of the original notebook into a runnable package —
same algorithms, same check order, same decisions — reorganized so it runs
from the command line instead of cell-by-cell, with secrets in `.env`
instead of in the code.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # fill in only what you actually use
```

The first YOLO segmentation call downloads `yolov8n-seg.pt` automatically —
no manual step needed.

## Quick start

```bash
# Register an original image (prompts for a vault passphrase on first run,
# which creates the secret vault; every later command asks for the same one)
python main.py register --image samples/original.jpg

# Check a suspect image against the registered ledger
python main.py verify --image samples/suspect.jpg --platform police_portal

# See the tamper-evident audit trail
python main.py audit

# Profile CPU time + peak memory for registration, across a folder of images
# (verification runs server-side and isn't the resource-constrained target,
# so only registration is profiled — see watermark/metrics.py)
python main.py profile --images samples/test_set/
```

Run `python main.py -h` for the full command list (also: `jpeg-attack`,
`backup-drive`, `sync-mongo`).

## Project layout

```
config.py                    All tunable constants + env-loaded secrets/paths
main.py                      CLI entrypoint — start here
watermark/
  crypto_vault.py             Passphrase-protected secret vault + AES-256-GCM image vault
  zero_watermark.py           YOLO ROI isolation, DWT/DCT key generation & extraction, NC scoring
  tamper_seal.py               Scattered LSB seal, MAD localisation, attack-type classifier
  metrics.py                   PSNR/SSIM/BER, phase timing, complexity estimate, CPU/memory profiler
  ledger.py                    HMAC-signed ledger, dual-hash blacklist, forensic audit log
  visualizers.py                One combined diagnostics figure (not four separate PNGs)
  pipeline.py                   run_registration() and run_gateway() — the two end-to-end flows
integrations/
  ipfs_storage.py                Pinata/IPFS backup — runs in the background, not in the critical path
  google_drive_backup.py         Drive backup (de-duplicated from 4 near-identical notebook cells)
  mongo_sync.py                  MongoDB Atlas sync
scripts/
  run_profiler.py                 CPU/memory profiler as a standalone script (also callable via `main.py profile`)
  batch_jpeg_attack.py             JPEG-recompression attack-sample generator
data/                              Everything runtime-generated lives here (gitignored): ledger, vault,
                                    secrets, logs, and outputs/{diagnostics,signed,heatmaps,recovered}/
```

## What changed vs. the notebook (and why)

- **Secrets moved to `.env`.** `MONGO_URI`, `PINATA_JWT`, the Google Drive
  folder id, and local file paths were hardcoded in the notebook. They're
  now read from environment variables only — see `.env.example`.
  **If you're carrying over a real Mongo Atlas password from the notebook,
  rotate it before putting it in `.env`** — a credential that ever sat in a
  shareable `.ipynb` file should be treated as already exposed.
- **One diagnostics figure instead of four.** `visualizers.py` combines the
  ROI/frequency/anchor/key plots into a single `registration_diagnostics.png`,
  and it's skippable entirely (`--no-diagnostics`) for batch/profiling runs,
  so plotting never pollutes a CPU/memory measurement.
- **All runtime data under `data/`.** Ledger, vault, logs, and generated
  images no longer scatter across the working directory — one gitignored
  folder, with clear subfolders for signed/recovered/heatmap outputs.
- **IPFS upload is now background/optional (`--backup-ipfs`)**, not inside
  the registration critical path — registration no longer waits on a
  third-party network call to finish.
- **Secrets load explicitly, not on import.** `crypto_vault.load_secrets()`
  is called once from `main.py`; importing a module never prompts for a
  passphrase as a side effect.
- **Google Drive backup logic de-duplicated** from four near-identical
  notebook cells into one function.
- **CPU-time + peak-memory profiling added** (`watermark/metrics.py`,
  `scripts/run_profiler.py`), scoped to registration only, excluding
  matplotlib and network calls from the measured window (see the module
  docstring for why).

## Known issues carried over as-is (not silently fixed here)

This port preserves the original algorithm's behavior faithfully — it does
**not** quietly change detection logic. A few things flagged in earlier
review are still present and worth fixing deliberately, on your own timeline:

1. **Resize-induced NC drift can cause false BLOCKs on legitimately resized
   images** (`extract_key_v3`'s anchor remap uses an approximation of the
   registered LL3 shape). The tamper-seal check already has a correct
   "benign resize" path; the NC/ownership check doesn't yet defer to it.
2. **No floor for "never registered" images.** The gateway currently reports
   `BLOCK (TAMPERED)` for content that was simply never submitted for
   registration, conflating "not in the system" with "tampered evidence."
   Worth a three-way evaluation split (registered-untampered /
   registered-tampered / never-registered) rather than two.
3. **Permanent blacklist, no appeal path** — a false positive currently
   locks an image out forever with no admin-override mechanism.
4. **pHash blacklist/ledger lookups are still linear scans.** Fine at your
   current scale; a BK-tree index over Hamming distance is the standard fix
   if this needs to handle a much larger registered set.

None of these needed to change to split the notebook into files, so they
weren't touched — flagging them here so they don't quietly get forgotten.
