#!/usr/bin/env python3
"""
main.py — Streamlined CLI for Traffic Image Watermarking & Authentication.

Usage:
    python3 main.py register <image_path>
    python3 main.py verify <image_path>
    python3 main.py audit
"""
import argparse
import sys
import os

import config
from watermark.crypto_vault import load_secrets
from watermark.pipeline import run_registration, run_gateway
from watermark.ledger import print_audit_trail


def main():
    parser = argparse.ArgumentParser(
        description="Relational Zero-Watermarking Evidence Authentication Gateway",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── REGISTER COMMAND ───────────────────────────────────────────────────────
    # Usage: python3 main.py register <image_path>
    reg_parser = subparsers.add_parser("register", help="Register image & auto-upload to IPFS")
    reg_parser.add_argument("image", help="Path to original image (e.g., 10357.png)")
    reg_parser.add_argument("--passphrase", "-p", default=None, help="Vault passphrase (omit to be prompted)")
    reg_parser.add_argument("--no-diagnostics", action="store_true", help="Skip saving diagnostic plots")

    # ── VERIFY COMMAND ─────────────────────────────────────────────────────────
    # Usage: python3 main.py verify <image_path>
    ver_parser = subparsers.add_parser("verify", help="Run full multi-stage verification on suspect image")
    ver_parser.add_argument("image", help="Path to suspect image (e.g., 10357_signed.png)")
    ver_parser.add_argument("--passphrase", "-p", default=None, help="Vault passphrase (omit to be prompted)")
    ver_parser.add_argument("--platform", default="police_portal",
                            choices=list(config.PLATFORMS.keys()),
                            help="Verification strictness threshold (default: police_portal)")
    ver_parser.add_argument("--auto-recover", action="store_true",
                            help="Automatically recover original from vault if tampered (no interactive prompt)")

    # ── AUDIT COMMAND (optional handy utility) ─────────────────────────────────
    audit_parser = subparsers.add_parser("audit", help="Display forensic audit trail")
    audit_parser.add_argument("--limit", type=int, default=None, help="Show last N events")

    args = parser.parse_args()

    # Load / Unlock secrets
    passphrase = getattr(args, "passphrase", None)
    load_secrets(passphrase)

    # Execute subcommand
    if args.command == "register":
        run_registration(
            image_path=args.image,
            save_diagnostics=not args.no_diagnostics,
            backup_ipfs=True  # Automatically uploads to IPFS every time!
        )

    elif args.command == "verify":
        # Runs full verification pipeline:
        # Pre-check -> Blacklist -> Ledger HMAC -> LSB Seal -> NC Zero-Watermark -> MAD Localization -> Recovery
        run_gateway(
            image_path=args.image,
            platform=args.platform,
            auto_recover=args.auto_recover
        )

    elif args.command == "audit":
        print_audit_trail(limit=args.limit)


if __name__ == "__main__":
    main()