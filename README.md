# Sentinel Vault 🛡️
> **Discord Archive Ingestion, Static Security Quarantine & Dual Storage Engine**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![UI: Dear PyGui](https://img.shields.io/badge/UI-Dear%20PyGui%20(ImGui)-indigo.svg)](https://github.com/hoffstadt/DearPyGui)

Sentinel Vault is an automated software ingestion, static security triage, and telemetry archive tool. It monitors Discord servers, scans released archives (`.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.dll`, `.sys`, `.exe`) in real time, quarantines embedded threats (token stealers, grabbers, hidden webhooks, malicious droppers), and stores sanitized releases in an organized taxonomy—either on **Local Disk** or in **Google Drive**.

---

## Key Features

- **Native ImGui Dark Dashboard**: Powered by [Dear PyGui](https://github.com/hoffstadt/DearPyGui) with standard ASCII typography (zero emoji/glyph glitching), real-time HUD telemetry, dark slate styling, and color-coded live logs.
- **Dual-Mode Storage Engine**:
  - **Local Disk (Default & Recommended)**: Store files directly in clean hierarchical game/tool directories on any local disk without cloud accounts or third-party CLI dependencies.
  - **Google Drive (Optional)**: Automatically provisions cloud directories and uploads files via the `gdrive` CLI with zero local disk footprint.
- **Deep Static Threat Quarantine**:
  - In-archive scanning for hardcoded Discord webhooks (`api/webhooks/...`).
  - Detection of Telegram C2 tokens, token grabbers (`BlankGrabber`, `W4SP`, `Lumma`, `RedLine`), and credential harvesting patterns (`CryptUnprotectData`, `Login Data`, `Cookies`).
  - Detection of obfuscated PowerShell, `certutil`, `bitsadmin`, and script droppers.
  - Automatic isolation into `Quarantine/` and safe renaming with `.quarantined` suffix.
- **Multi-Game Taxonomy & Dedicated Tool Matrix**:
  - Automatically identifies projects for Fortnite, Counter-Strike 2, CS:GO, Rust, GTA V / FiveM, Roblox, Minecraft Java/Bedrock, Rainbow Six Siege, and more.
  - Strict separation of External cheats into **Kernel** and **UserMode**.
  - Dedicated sections for **Tools/Drivers/** (EAC, BattlEye, Vanguard) and **Tools/Mappers/** (KDMapper, VDM, DrvMap).
- **Content Hash Deduplication**: Calculates SHA-256 signatures for every candidate release to eliminate duplicate downloads and redundant disk usage.

---

## Architecture Overview

```
sentinel-vault/
├── config/
│   └── config.template.json    # Sanitized configuration template
├── core/
│   ├── discord_client.py       # Discord REST API client with auto 429 rate-limit backoff
│   ├── security_scanner.py     # Static AST, byte, and archive threat scanner
│   ├── triage_engine.py        # Multi-game and tool taxonomy classifier
│   ├── storage_manager.py      # Dual-mode storage engine (Local Disk & Google Drive)
│   └── pipeline_runner.py      # Threaded orchestrator with real-time UI event callbacks
├── ui/
│   └── imgui_dashboard.py      # Native Dear PyGui ImGui dashboard
├── app.py                      # Main entry point (GUI or --cli headless)
├── requirements.txt            # Python dependencies
├── .gitignore                  # Prevents accidental credential/token commits
└── README.md
```

---

## Quickstart

### 1. Prerequisites
- Python 3.10, 3.11, or 3.12
- Git

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/your-username/sentinel-vault.git
cd sentinel-vault

# Install dependencies
pip install -r requirements.txt
```

### 3. Launching the ImGui Dashboard
```bash
python app.py
```

### 4. Running Headless (CLI Mode)
For servers, cron jobs, or headless container environments:
```bash
python app.py --cli
```

---

## Using the ImGui Interface

1. **Discord Configuration**:
   - Paste your Discord authorization token in the password-masked field.
   - Paste the Server (Guild) IDs you wish to monitor into the multi-line text box (one ID per line).
   - Adjust the message history depth slider (50 to 2,000 messages per channel).
2. **Select Storage Target**:
   - **Local Disk**: Select a destination directory (e.g. `D:/MyVault` or `./vault_storage`) using the **Browse...** button.
   - **Google Drive**: Select Google Drive mode and enter your Google account email and optional root folder ID.
3. **Security Rules**:
   - In-Archive Threat Scanning and Content Deduplication are enabled by default.
4. **Execution**:
   - Click **`START PIPELINE`**.
   - Monitor live progress in the color-coded console and real-time metric cards.
   - Click **`Open Vault`** at any time to inspect your organized local files in Windows Explorer.

---

## Stored Directory Taxonomy

When running in **Local Disk** mode, your chosen directory is organized automatically:

```
<Local_Storage_Path>/
├── Games/
│   ├── Fortnite/
│   │   ├── External/
│   │   │   ├── Kernel/
│   │   │   └── UserMode/
│   │   └── Internal/
│   │       ├── DLL/
│   │       └── Injectors/
│   ├── CounterStrike_CS2/
│   │   ├── External/
│   │   │   ├── Kernel/
│   │   │   └── UserMode/
│   │   └── Internal/
│   │       ├── DLL/
│   │       └── Injectors/
│   ├── CounterStrike_CSGO/
│   │   ├── External/
│   │   └── Internal/
│   └── Rust/
│       ├── External/
│       │   ├── Kernel/
│       │   └── UserMode/
│       └── Internal/
├── Tools/
│   ├── Drivers/             <-- Dedicated kernel drivers (EAC, BE, Vanguard, General)
│   ├── Mappers/             <-- Dedicated mappers (KDMapper, VDM, DrvMap)
│   ├── Injectors/           <-- Standalone injectors
│   └── Dumpers/             <-- Offset / SDK / Schema dumpers
├── Spoofer/
│   └── Universal/
│       ├── Temp/
│       └── Perm/
├── Other/
│   ├── Cheats/
│   │   ├── External/
│   │   │   ├── Kernel/
│   │   │   └── UserMode/
│   │   └── Internal/
│   │       └── DLL/
│   └── Utilities/
└── Quarantine/
    ├── Detected_Viruses/    (*.quarantined)
    └── Suspicious_Stealers/ (*.quarantined)
```

---

## Security & Privacy Notice

- **Zero Hardcoded Secrets**: This repository contains no hardcoded credentials, API keys, or Discord tokens.
- **Git Protection**: Your private configuration (`config/config.json`) and local vaults are explicitly listed in `.gitignore` to prevent leaking credentials.
- **Authorized Use**: This software is intended for local security research, personal archive curation, and malware analysis in controlled environments.

---

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
