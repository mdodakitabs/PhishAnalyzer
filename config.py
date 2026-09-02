#!/usr/bin/env python3
"""
config.py — PhishAnalyzer v5.0
Decrypts the VirusTotal API key into RAM only, on demand,
without ever writing it to disk in plain text.

Supports two optional paths for secret.key:
1. The default path inside the project folder (less secure).
2. A separate external path such as ~/.phishanalyzer/secret.key (recommended).
"""

import os
import sys
import ctypes

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    sys.exit("[!] The 'cryptography' library is not installed. Install it with: pip install cryptography")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Change this path if you moved secret.key outside the project folder (recommended)
EXTERNAL_KEY_PATH = os.path.expanduser("~/.phishanalyzer/secret.key")
LOCAL_KEY_PATH = os.path.join(BASE_DIR, "secret.key")
ENC_PATH = os.path.join(BASE_DIR, "encrypted_api.txt")

# --- General tool settings ---
REQUEST_TIMEOUT = 10           # seconds, for network requests (VT / SSL / WHOIS)
DOMAIN_AGE_THRESHOLD_DAYS = 90  # threshold for "new and suspicious domain"
DOMAIN_AGE_RISK_BOOST = 35      # risk points added if the domain is newer than the threshold
HISTORY_FILE = os.path.join(BASE_DIR, "scans_history.txt")
VT_API_BASE = "https://www.virustotal.com/api/v3"


def _resolve_key_path() -> str:
    if os.path.exists(EXTERNAL_KEY_PATH):
        return EXTERNAL_KEY_PATH
    if os.path.exists(LOCAL_KEY_PATH):
        return LOCAL_KEY_PATH
    sys.exit(
        "[!] secret.key was not found.\n"
        "    Run setup_crypto.py first to set up encryption."
    )


def _wipe_bytes(buf: bytearray) -> None:
    """Best-effort attempt to zero out a mutable byte buffer in memory."""
    try:
        length = len(buf)
        offset = (ctypes.c_char * length).from_buffer(buf)
        ctypes.memset(ctypes.addressof(offset), 0, length)
    except Exception:
        pass


def get_vt_api_key() -> str:
    """
    Decrypts and returns the VirusTotal API key.
    Called lazily, only when needed, rather than at module import time,
    to minimize how long the key stays in plain form in memory.
    """
    if not os.path.exists(ENC_PATH):
        sys.exit("[!] encrypted_api.txt was not found. Run setup_crypto.py first.")

    key_path = _resolve_key_path()

    with open(key_path, "rb") as f:
        fernet_key = f.read()
    with open(ENC_PATH, "rb") as f:
        encrypted_token = f.read()

    fernet = Fernet(fernet_key)
    try:
        decrypted = fernet.decrypt(encrypted_token)
    except InvalidToken:
        sys.exit("[!] Decryption failed: the key or the encrypted file is corrupted/mismatched.")

    api_key = decrypted.decode("utf-8")

    # Best-effort wipe of intermediate copies (Python cannot guarantee this 100%)
    mutable_copy = bytearray(decrypted)
    _wipe_bytes(mutable_copy)
    del decrypted, mutable_copy, fernet_key

    return api_key
