#!/usr/bin/env python3
"""
main.py — PhishAnalyzer v5.0
Text-based interface for analyzing phishing URLs.
Runs entirely inside Termux on Android, no Root required.
"""

import os
import sys
from datetime import datetime

from config import HISTORY_FILE, get_vt_api_key
from core_rules import analyze_url

BANNER = r"""
 ____  _     _     _                  _
|  _ \| |__ (_)___| |__   __ _ _ __  | |    __ _ ___
| |_) | '_ \| / __| '_ \ / _` | '_ \ | |   / _` / __|
|  __/| | | | \__ \ | | | (_| | | | | |__| (_| \__ \
|_|   |_| |_|_|___/_| |_|\__,_|_| |_|_____\__,_|___/

        PhishAnalyzer v5.0 — No-Root Edition
"""


def log_scan(result) -> None:
    line = (
        f"[{datetime.now().isoformat(timespec='seconds')}] "
        f"{result.url} | Risk={result.risk_score} | {result.verdict()}\n"
    )
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def print_result(result) -> None:
    print("\n" + "=" * 55)
    print(f" URL    : {result.url}")
    print(f" Score  : {result.risk_score}/100  —  {result.verdict()}")
    print("=" * 55)

    if result.domain_age_days is not None:
        print(f" Domain age : {result.domain_age_days} days")
    if result.ssl_valid is not None:
        print(f" SSL cert   : {'Valid' if result.ssl_valid else 'Invalid/Missing'}")
    if result.vt_result:
        print(f" VirusTotal : {result.vt_result}")

    print("\n Details:")
    if result.findings:
        for f in result.findings:
            print(f"   - {f}")
    else:
        print("   No significant risk indicators found.")
    print()


def view_history() -> None:
    if not os.path.exists(HISTORY_FILE):
        print("\n[i] No scan history yet.\n")
        return
    print("\n--- Previous Scan History ---")
    with open(HISTORY_FILE, encoding="utf-8") as f:
        print(f.read())


def scan_flow(api_key: str | None) -> None:
    url = input("\n[?] Enter the URL to scan: ").strip()
    if not url:
        print("[!] No URL entered.")
        return
    print("[*] Analyzing, this may take a few seconds (WHOIS/SSL/VirusTotal)...")
    result = analyze_url(url, api_key=api_key)
    print_result(result)
    log_scan(result)


def main() -> None:
    print(BANNER)

    api_key = None
    try:
        api_key = get_vt_api_key()
        print("[+] VirusTotal API key loaded successfully (decrypted temporarily in memory).")
    except SystemExit as e:
        print(f"[!] {e}")
        print("[i] Continuing without the VirusTotal cloud scan.")

    while True:
        print("\n" + "-" * 40)
        print(" [1] Scan a new URL")
        print(" [2] View scan history")
        print(" [3] Exit")
        choice = input(" Choose: ").strip()

        if choice == "1":
            scan_flow(api_key)
        elif choice == "2":
            view_history()
        elif choice == "3":
            print("Goodbye \U0001F44B")
            sys.exit(0)
        else:
            print("[!] Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Program stopped by user.")
        sys.exit(0)
