# Sentinel Vault

> **Automated Discord Archive Scraper, Static Threat Quarantine & Dual Storage Engine**

Sentinel Vault is an automated tool that connects to your Discord servers, downloads software archives (`.zip`, `.rar`, `.7z`, `.dll`, `.sys`, `.exe`), analyzes their contents for malware, and neatly organizes them into a structured taxonomy on your **Local Disk** or in **Google Drive**.

Everything runs directly on your computer through a native **ImGui Dark Mode** dashboard.

---

## Key Features

- **Modern ImGui Dashboard**: Built with [Dear PyGui](https://github.com/hoffstadt/DearPyGui) for high-performance desktop rendering, color-coded live logs, and zero glyph/emoji glitches.
- **Dual Storage Options**:
  - **Local Disk (Default)**: Store files directly into clean game/tool folders on your drive. No cloud account or external tools required.
  - **Google Drive (Optional)**: Automatically mirror your organized vault to Google Drive via the official `gdrive` CLI.
- **In-Archive Threat Quarantine**:
  - Unpacks and statically inspects `.zip`, `.rar`, `.7z`, and `.tar` archives in memory before saving.
  - Detects hidden Discord webhooks, Telegram C2 tokens, token grabbers (BlankGrabber, W4SP, Lumma, RedLine), credential theft routines, and malicious PowerShell droppers.
  - Automatically renames infected files with a `.quarantined` extension into `Quarantine/`.
- **Hybrid AI & Heuristic Classification**:
  - Automatically identifies games (Fortnite, Counter-Strike 2, Rust, Roblox, etc.) and separates projects into `External/Kernel/`, `External/UserMode/`, `Internal/DLL/`, and `Internal/Injectors/`.
  - Dedicated sections for `Tools/Drivers/` (EAC, BattlEye, Vanguard) and `Tools/Mappers/` (KDMapper, VDM, DrvMap).
- **Duplicate Prevention**: SHA-256 hash checks prevent redundant downloads and save storage space.

---

## AI & Classification Engine: How it Works

Sentinel Vault uses a **2-stage classification system** so it works out of the box without requiring paid API keys:

```
[ Discord Attachment ]
          │
          ▼
[ Static Threat Scanner ] ──(Threat Found)──► [ Quarantine/ (*.quarantined) ]
          │ (Clean)
          ▼
{ Is AI Enabled in GUI? }
  ├──► YES: Uses LLM (Gemini / OpenAI / Ollama) to analyze folder tree & context
  └──► NO:  Uses Built-in Offline Signature Analyzer (AST, .sys detection, class names)
          │
          ▼
[ Clean Vault Storage: Local Disk or Google Drive ]
```

### 1. Offline Signature Engine (100% Free & Zero-Config)
By default, Sentinel Vault scans archive contents for known engineering signatures:
- **Drivers & Mappers**: Detects `DriverEntry`, `IoCreateDevice`, `kdmapper`, `vdm`, `drvmap`, etc.
- **Game Signatures**: Detects Unreal Engine / Source 2 symbols (`UWorld`, `dwLocalPlayerPawn`, `BasePlayer`).
- **Cheat Architecture**: Automatically groups code into `Kernel`, `UserMode`, `DLL`, or `Injectors`.

### 2. Optional Neural AI Classifier
If enabled in the **Security & Automation** tab, Sentinel Vault can consult an AI model for ambiguous repositories:
- **Google Gemini API (Free Tier)**: Recommended model `gemini-1.5-flash` or `gemini-2.0-flash`. Very fast and completely free for personal use.
- **OpenAI**: Supports `gpt-4o-mini` or any standard chat model.
- **Local Ollama (Offline)**: Use offline open-weight models (`llama3`, `mistral`, `deepseek-r1`) via `http://localhost:11434`.

---

## Source Code & Project Structure

All modules are documented and self-contained in the `core/` and `ui/` directories:

```
sentinel-vault/
├── config/
│   └── config.template.json    # Default template (no personal secrets)
├── core/
│   ├── discord_client.py       # Multi-server Discord client with 429 rate-limit backoff
│   ├── security_scanner.py     # In-archive static threat scanner & AST regex rules
│   ├── triage_engine.py        # 2-layer taxonomy sorter (Games, Drivers, Mappers)
│   ├── ai_classifier.py        # Neural LLM integration (Gemini, OpenAI, Ollama)
│   ├── storage_manager.py      # Dual-mode engine (Local Disk & Google Drive)
│   └── pipeline_runner.py      # Multi-threaded background orchestrator
├── ui/
│   └── imgui_dashboard.py      # Dear PyGui dark-mode desktop interface
├── app.py                      # Main application entry point (GUI or --cli)
├── start_discord_scan.bat      # 1-click portable Windows starter
├── requirements.txt            # Python package dependencies
└── README.md
```

---

## Beginner Guide: Installation & Setup

### Step 1: Install Python
1. Download Python 3.10 or newer from [python.org](https://www.python.org/downloads/).
2. **Important**: When installing on Windows, check the box **"Add python.exe to PATH"**.

### Step 2: Download the Project
Open PowerShell or Command Prompt:
```bash
git clone https://github.com/<YOUR-USERNAME>/sentinel-vault.git
cd sentinel-vault
```
*(Alternatively, click the green **Code -> Download ZIP** button on GitHub and extract the folder).*

### Step 3: Install Dependencies
Run this single command to install Dear PyGui:
```bash
pip install -r requirements.txt
```

### Step 4: Start the Dashboard
Double-click `start_discord_scan.bat` or run:
```bash
python app.py
```

---

## Quickstart: How to Run Your First Scan

1. **Tab 1: Discord Credentials & Targets**:
   - Paste your Discord Authorization Token into the masked field (click **Test Token** to verify).
   - Paste one or more **Discord Server IDs** into the servers box (one ID per line).
   - Choose how many past messages to scan per channel (default: 500).
2. **Tab 2: Storage Target**:
   - Select **Local Disk Directory** and click **Browse...** to pick any folder on your PC (e.g. `C:/MyVault`).
   - *(Optional)* Choose Google Drive if you use the `gdrive` CLI.
3. **Tab 3: Security & AI (Optional)**:
   - Threat scanning is active by default.
   - If you want AI categorization, check **Enable AI Neural Categorization**, pick **Gemini API**, and enter your free Gemini key.
4. **Tab 4: Ingestion Console**:
   - Click **`START PIPELINE`**.
   - Watch real-time downloads, scanner verdicts, and clean sorting in the console.
   - Click **`Open Vault`** at any time to open your sorted folders in Windows Explorer.

---

## Vault Directory Layout

Files are automatically organized cleanly:

```
Vault_Storage/
├── Games/
│   ├── Fortnite/
│   │   ├── External/ (Kernel / UserMode)
│   │   └── Internal/ (DLL / Injectors)
│   ├── CounterStrike_CS2/
│   │   ├── External/ (Kernel / UserMode)
│   │   └── Internal/ (DLL / Injectors)
│   ├── Rust/
│   ├── Roblox/
│   └── Grand_Theft_Auto_V/
├── Tools/
│   ├── Drivers/             # Kernel drivers (EAC, BattlEye, Vanguard)
│   ├── Mappers/             # Mappers (KDMapper, VDM, DrvMap)
│   ├── Injectors/           # Standalone DLL injectors
│   └── Dumpers/             # Offsets, SDK & Schema dumpers
├── Spoofer/
│   └── Universal/ (Temp / Perm)
├── Other/
│   └── Utilities/
└── Quarantine/
    ├── Detected_Viruses/    # Dangerous archives (*.quarantined)
    └── Suspicious_Stealers/ # Token grabbers & webhooks (*.quarantined)
```

---

## Privacy & Security

- **Zero Hardcoded Secrets**: This repository does not contain any pre-configured tokens, server IDs, or API keys.
- **Git Protected**: Private user settings (`config/config.json`) and downloaded storage folders are excluded via `.gitignore` to prevent accidental commits.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
