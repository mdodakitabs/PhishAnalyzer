#!/usr/bin/env python3
"""
setup_crypto.py — PhishAnalyzer v5.0
Run this once to generate a symmetric encryption key (Fernet/AES)
and encrypt the VirusTotal API key before it is written to disk.

Security notes:
- secret.key and encrypted_api.txt are created with 600 permissions
  (read/write for the owner only).
- The raw API key is never echoed to the screen after input (getpass).
- Strongly recommended: move secret.key outside the project folder
  (e.g. ~/.phishanalyzer/) so the key and the encrypted file are not
  sitting together if the project folder is ever leaked (accidental
  git push, full folder copy, etc.).
"""

import os
import sys
import stat
import getpass

try:
    from cryptography.fernet import Fernet
except ImportError:
    sys.exit(
        "[!] The 'cryptography' library is not installed.\n"
        "    Install it with: pip install cryptography"
    )

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(BASE_DIR, "secret.key")
ENC_PATH = os.path.join(BASE_DIR, "encrypted_api.txt")


def secure_write(path: str, data: bytes) -> None:
    """Write the file, then restrict its permissions to the owner only (600)."""
    with open(path, "wb") as f:
        f.write(data)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 600
    except (OSError, NotImplementedError):
        # Some Termux environments may not fully support chmod;
        # fail silently rather than breaking the setup flow.
        pass


def main() -> None:
    if os.path.exists(KEY_PATH) or os.path.exists(ENC_PATH):
        print("[!] An encrypted key already exists for this project.")
        confirm = input("    Do you want to replace it with a new key? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("[*] Cancelled. Nothing was changed.")
            return

    print("=" * 50)
    print(" PhishAnalyzer v5.0 — Initial Crypto Setup")
    print("=" * 50)

    api_key = getpass.getpass("[?] Enter your VirusTotal API key (input hidden): ").strip()

    if not api_key:
        sys.exit("[!] No key was entered. Aborting.")

    if len(api_key) < 32:
        print("[!] Warning: this length is unusual for a VirusTotal key (normally 64 chars). "
              "Double-check you copied it correctly.")

    # Generate a new Fernet key (AES-128-CBC + HMAC)
    fernet_key = Fernet.generate_key()
    fernet = Fernet(fernet_key)

    encrypted_token = fernet.encrypt(api_key.encode("utf-8"))

    secure_write(KEY_PATH, fernet_key)
    secure_write(ENC_PATH, encrypted_token)

    # Wipe the sensitive variable from memory as soon as possible
    api_key = "0" * len(api_key)
    del api_key

    print("\n[+] Encryption and storage completed successfully.")
    print(f"    - Decryption key : {KEY_PATH}")
    print(f"    - Encrypted token: {ENC_PATH}")
    print("\n[!] Important security note:")
    print("    Together, these two files are enough to recover your original key.")
    print("    It is recommended to move secret.key to a separate path outside")
    print("    this folder, for example:")
    print("      mkdir -p ~/.phishanalyzer && mv secret.key ~/.phishanalyzer/")
    print("    Then update the corresponding path in config.py.")


if __name__ == "__main__":
    main()
