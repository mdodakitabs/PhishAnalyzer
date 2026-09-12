# PhishAnalyzer v5.0 — No-Root Edition

A phishing and social-engineering link analysis tool that runs entirely
inside Termux on Android, no Root required.

## Installation on Termux

```bash
pkg update && pkg upgrade -y
pkg install python git -y
git clone <your_repository_url> PhishAnalyzer
cd PhishAnalyzer
pip install -r requirements.txt
```

## Initial Setup (one time only)

```bash
python setup_crypto.py
```

You will be prompted to enter your VirusTotal API key (free from
virustotal.com). It will be encrypted and stored locally.

> **Recommended:** move `secret.key` outside the project folder after
> generation:
> ```bash
> mkdir -p ~/.phishanalyzer && mv secret.key ~/.phishanalyzer/
> ```

## Running the Tool

```bash
python main.py
```

### Enabling the global `phishanalyzer` command

Add the following line to `~/.bashrc`:

```bash
alias phishanalyzer="python /full/absolute/path/to/PhishAnalyzer/main.py"
```

Then:

```bash
source ~/.bashrc
```

After that, you can run the tool from anywhere by typing:

```bash
phishanalyzer
```

## Project Structure

```
PhishAnalyzer/
├── setup_crypto.py    # Generates and encrypts the API key (run once)
├── secret.key          # Decryption key (auto-generated, never share it)
├── encrypted_api.txt   # Encrypted VT key (auto-generated)
├── config.py            # Settings + in-memory-only decryption
├── core_rules.py         # Analysis engine (Static/SSL/WHOIS/VirusTotal)
├── main.py                # Command-line interface
└── scans_history.txt      # Scan log (auto-generated)
```

## Security Notice

- Never share `secret.key` or `encrypted_api.txt`,and never commit them
  to Git. They are already listed in `.gitignore`.
- This tool is intended for defensive use only (analyzing suspicious
  links you received), not as an offensive/attack tool.
