"""
ipfs_storage.py — Pinata/IPFS backup of encrypted vault files.

CHANGE from the original notebook: IPFS upload used to run synchronously
inside encrypt_image(), so registration blocked on a network round-trip to
a third party. IPFS is a redundancy/backup layer, not part of the
watermarking algorithm itself, so it doesn't belong in that critical path.
Here it's fire-and-forget: call backup_to_ipfs_async() after registration
completes; it uploads on a background thread and patches the ledger's
ipfs_cid field in place once the upload finishes (or leaves it None on
failure/timeout — registration itself never blocks on this).
"""
"""
ipfs_storage.py — Pinata/IPFS backup of encrypted vault files.

Provides:
  - upload_to_ipfs(filepath): Direct upload of .enc file to Pinata IPFS.
  - download_from_ipfs(cid, dest_path): Retrieval of .enc file from IPFS gateway.
  - backup_to_ipfs_sync(vault_path, img_hash): Synchronous backup & ledger patch.
  - backup_to_ipfs_async(vault_path, img_hash): Non-blocking background backup.
"""
import json
import os
import sys
import threading
import requests

import config


def upload_to_ipfs(filepath: str) -> str:
    """Uploads the AES .enc file to Pinata IPFS and returns the CID."""
    pinata_jwt = getattr(config, "PINATA_JWT", None)
    if not pinata_jwt or pinata_jwt.strip() in ("", "YOUR PINATA JWT"):
        print("⚠️  PINATA_JWT not configured in config.py or .env — skipping IPFS upload.")
        return None

    if not os.path.exists(filepath):
        print(f"❌ Cannot upload to IPFS: File does not exist -> {filepath}")
        return None

    filename = os.path.basename(filepath)
    print(f"⏳ Uploading {filename} to Pinata IPFS Vault...")

    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {"Authorization": f"Bearer {pinata_jwt.strip()}"}

    try:
        with open(filepath, "rb") as file_data:
            files = {"file": (filename, file_data)}
            response = requests.post(url, files=files, headers=headers, timeout=60)

        if response.status_code == 200:
            cid = response.json().get("IpfsHash")
            print(f"✅ Locked in IPFS! CID: {cid}")
            return cid
        else:
            print(f"❌ IPFS upload failed ({response.status_code}): {response.text}")
            return None
    except requests.exceptions.Timeout:
        print("❌ IPFS upload failed: Request timed out after 60s.")
        return None
    except Exception as e:
        print(f"❌ IPFS upload encountered an unexpected error: {e}")
        return None


def download_from_ipfs(cid: str, dest_path: str) -> str:
    """Downloads the .enc file from IPFS using a public gateway."""
    if not cid:
        raise ValueError("Invalid CID provided for IPFS download.")

    print(f"⏳ Recovering from IPFS Vault (CID: {cid[:12]}...)...")
    
    # Try multiple gateways in case one is congested
    gateways = [
        f"https://gateway.pinata.cloud/ipfs/{cid}",
        f"https://ipfs.io/ipfs/{cid}",
        f"https://cloudflare-ipfs.com/ipfs/{cid}"
    ]

    for gateway_url in gateways:
        try:
            response = requests.get(gateway_url, timeout=25)
            if response.status_code == 200:
                os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
                with open(dest_path, "wb") as f:
                    f.write(response.content)
                print(f"✅ Vault file recovered from IPFS -> {dest_path}")
                return dest_path
        except requests.exceptions.RequestException:
            continue

    raise RuntimeError(f"❌ IPFS download failed: All public gateways timed out or rejected CID: {cid}")


def _patch_ledger_cid(img_hash: str, cid: str):
    """
    Writes the returned CID into the local registration ledger entry
    and re-signs the record with HMAC to preserve integrity.
    """
    # Safe import handling regardless of PYTHONPATH setup
    try:
        from watermark.ledger import _sign_record
    except ImportError:
        try:
            from ledger import _sign_record
        except ImportError:
            # Absolute fallback if called outside root
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from watermark.ledger import _sign_record

    if not os.path.exists(config.LEDGER_FILE):
        return

    try:
        with open(config.LEDGER_FILE, "r") as f:
            ledger = json.load(f)

        if img_hash not in ledger:
            return

        record = ledger[img_hash]
        record.pop("hmac_sig", None)
        record["ipfs_cid"] = cid
        record["hmac_sig"] = _sign_record(dict(record))
        ledger[img_hash] = record

        with open(config.LEDGER_FILE, "w") as f:
            json.dump(ledger, f, indent=2)

        print(f"🔒 Ledger updated & signed with IPFS CID for [{img_hash[:8]}...]")
    except Exception as e:
        print(f"⚠️  Failed to patch ledger with IPFS CID: {e}")


def backup_to_ipfs_sync(vault_path: str, img_hash: str) -> str:
    """
    Synchronous IPFS backup. Recommended for standalone scripts or CLI commands
    so the Python process doesn't exit before the network upload completes.
    """
    cid = upload_to_ipfs(vault_path)
    if cid:
        _patch_ledger_cid(img_hash, cid)
    return cid


def backup_to_ipfs_async(vault_path: str, img_hash: str) -> threading.Thread:
    """
    Background worker that uploads vault_path to IPFS without blocking
    the main thread. Returns the Thread object.
    """
    def _worker():
        try:
            cid = upload_to_ipfs(vault_path)
            if cid:
                _patch_ledger_cid(img_hash, cid)
        except Exception as e:
            print(f"⚠️  Background IPFS backup failed for {img_hash[:8]}...: {e}")

    # daemon=False prevents Python from terminating the thread prematurely upon script exit
    t = threading.Thread(target=_worker, daemon=False)
    t.start()
    return t