"""
google_drive_backup.py — pushes the JSON ledger/blacklist/log files to a
Google Drive folder for off-machine backup.

CHANGE from the original notebook: this exact logic was duplicated across
four separate cells (13/17 and two more) with a hardcoded personal path
(/Users/.../Desktop/...) and a hardcoded Drive folder id in each copy. It's
one function here, and every path/id comes from config (i.e. from your
.env file) — see .env.example.
"""
import os
import pickle
import zipfile

import config

BACKUP_FILES = [
    "registration_ledger.zip",
    "tamper_blacklist.json",
    "tamper_log.json",
    "delivery_log.json",
    "gateway_results.json",
    "forensic_audit_log.json",
]

SCOPES = ["https://www.googleapis.com/auth/drive"]


def _zip_ledger() -> str:
    """Compress the ledger before upload (this is the file-size hygiene fix
    discussed earlier: the ledger's m_buffer/master_key arrays compress
    very well, easily 10x, since they're mostly repeated binary values)."""
    zip_path = os.path.join(config.DATA_DIR, "registration_ledger.zip")
    if not os.path.exists(config.LEDGER_FILE):
        return zip_path
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.write(config.LEDGER_FILE, arcname="registration_ledger.json")
    orig_kb = os.path.getsize(config.LEDGER_FILE) / 1024
    zip_kb = os.path.getsize(zip_path) / 1024
    print(f"   Ledger compressed: {orig_kb:.1f} KB -> {zip_kb:.1f} KB "
          f"({100 * (1 - zip_kb / orig_kb):.0f}% smaller)" if orig_kb else "")
    return zip_path


def _authenticate():
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    creds = None
    if os.path.exists(config.GOOGLE_TOKEN_FILE):
        with open(config.GOOGLE_TOKEN_FILE, "rb") as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(config.GOOGLE_CREDENTIALS_FILE):
                raise FileNotFoundError(
                    f"Google OAuth client secret not found at {config.GOOGLE_CREDENTIALS_FILE} "
                    f"(set GOOGLE_CREDENTIALS_FILE in .env)."
                )
            flow = InstalledAppFlow.from_client_secrets_file(config.GOOGLE_CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(config.GOOGLE_TOKEN_FILE, "wb") as token:
            pickle.dump(creds, token)
    return build("drive", "v3", credentials=creds)


def backup_to_drive():
    from googleapiclient.http import MediaFileUpload

    if not config.GOOGLE_DRIVE_FOLDER_ID:
        raise ValueError("GOOGLE_DRIVE_FOLDER_ID not set - see .env.example")

    _zip_ledger()
    service = _authenticate()

    print("=" * 60)
    print("  BACKING UP FILES TO GOOGLE DRIVE")
    print("=" * 60)
    uploaded, skipped = 0, 0
    for filename in BACKUP_FILES:
        file_path = os.path.join(config.DATA_DIR, filename)
        print(f"\nProcessing: {filename}")
        if not os.path.exists(file_path):
            print("  not found, skipping")
            skipped += 1
            continue
        mime_type = "application/zip" if filename.endswith(".zip") else "application/json"
        media = MediaFileUpload(file_path, mimetype=mime_type, resumable=True)
        try:
            uploaded_file = service.files().create(
                body={"name": filename, "parents": [config.GOOGLE_DRIVE_FOLDER_ID]},
                media_body=media, fields="id,name,size",
            ).execute()
            print(f"  uploaded: {uploaded_file['name']}")
            uploaded += 1
        except Exception as e:
            print(f"  upload failed: {e}")
            skipped += 1

    print("\n" + "=" * 60)
    print(f"BACKUP SUMMARY  |  uploaded={uploaded}  skipped={skipped}")
    print("=" * 60)
    return uploaded, skipped
