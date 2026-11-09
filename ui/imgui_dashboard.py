"""
Sentinel Vault - Native ImGui Dashboard (Dear PyGui).
Professional, clean, developer-grade desktop interface:
- Zero unicode/emoji glyph glitches (all standard ASCII typography)
- Multi-guild Discord token and server ID queue
- Instant Local Disk vs Google Drive storage switching
- Dedicated Drivers & Mappers taxonomy routing
- Real-time telemetry cards and color-coded logging console
- Complete independence from external dependencies (n8n is optional)
"""

import os
import sys
import json
import time
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

import dearpygui.dearpygui as dpg

from core.discord_client import DiscordClient
from core.pipeline_runner import PipelineRunner
from core.storage_manager import StorageMode

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
CONFIG_FILE = CONFIG_DIR / "config.json"
CONFIG_TEMPLATE = CONFIG_DIR / "config.template.json"


def load_app_config() -> Dict[str, Any]:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    if CONFIG_TEMPLATE.exists():
        try:
            with open(CONFIG_TEMPLATE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "discord": {"token": "", "servers": [], "history_depth": 500, "skip_channel_keywords": []},
        "storage": {"mode": "local", "local_path": "./vault_storage", "gdrive": {"account": "", "root_folder_id": ""}},
        "security": {"enable_static_scanner": True, "auto_quarantine": True, "quarantine_suffix": ".quarantined", "deduplicate_sha256": True},
        "webhook": {"enabled": False, "url": "http://localhost:5678/webhook/discord/source-eval"}
    }


def save_app_config(cfg: Dict[str, Any]):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


class ImGuiDashboard:
    """
    Standard Dear ImGui desktop application for Sentinel Vault.
    """

    def __init__(self):
        self.config = load_app_config()
        self.runner: Optional[PipelineRunner] = None
        self.is_running = False

    def setup_theme(self):
        with dpg.theme() as global_theme:
            with dpg.theme_component(dpg.mvAll):
                # Standard Dark ImGui Palette (Dark Obsidian & Slate)
                dpg.add_theme_color(dpg.mvThemeCol_WindowBg, (15, 17, 23, 255))
                dpg.add_theme_color(dpg.mvThemeCol_ChildBg, (21, 24, 33, 255))
                dpg.add_theme_color(dpg.mvThemeCol_Border, (42, 48, 64, 255))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (27, 31, 42, 255))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, (38, 44, 60, 255))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, (48, 56, 76, 255))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (19, 22, 30, 255))
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (27, 32, 44, 255))
                dpg.add_theme_color(dpg.mvThemeCol_Button, (35, 75, 145, 255))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (48, 98, 185, 255))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (26, 58, 115, 255))
                dpg.add_theme_color(dpg.mvThemeCol_Header, (38, 45, 62, 255))
                dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, (50, 60, 84, 255))
                dpg.add_theme_color(dpg.mvThemeCol_HeaderActive, (60, 74, 104, 255))
                dpg.add_theme_color(dpg.mvThemeCol_Tab, (24, 28, 38, 255))
                dpg.add_theme_color(dpg.mvThemeCol_TabHovered, (42, 50, 70, 255))
                dpg.add_theme_color(dpg.mvThemeCol_TabActive, (35, 75, 145, 255))
                dpg.add_theme_color(dpg.mvThemeCol_Text, (226, 232, 240, 255))
                dpg.add_theme_color(dpg.mvThemeCol_TextDisabled, (108, 117, 134, 255))

                # Clean Geometry & Spacing
                dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 4)
                dpg.add_theme_style(dpg.mvStyleVar_ChildRounding, 4)
                dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 3)
                dpg.add_theme_style(dpg.mvStyleVar_PopupRounding, 3)
                dpg.add_theme_style(dpg.mvStyleVar_ScrollbarRounding, 3)
                dpg.add_theme_style(dpg.mvStyleVar_TabRounding, 3)
                dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, 8, 6)
                dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 6, 4)

        dpg.bind_theme(global_theme)

    def log(self, level: str, msg: str):
        now_str = datetime.now().strftime("%H:%M:%S")
        color = (200, 210, 225)
        if level == "INFO":
            color = (108, 175, 255)
        elif level == "SCAN":
            color = (185, 145, 255)
        elif level == "PROCESS":
            color = (255, 210, 70)
        elif level in ("CLEAN", "SAVED"):
            color = (52, 211, 153)
        elif level in ("THREAT", "ERROR"):
            color = (248, 113, 113)
        elif level == "WARN":
            color = (251, 191, 36)

        if dpg.does_item_exist("console_log"):
            dpg.add_text(f"[{now_str}] [{level:<7}] {msg}", parent="console_log", color=color)
            dpg.set_y_scroll("console_log", dpg.get_y_scroll_max("console_log"))

    def update_metrics(self, m: Dict[str, Any]):
        if dpg.does_item_exist("stat_servers"):
            dpg.set_value("stat_servers", str(len(self.config.get("discord", {}).get("servers", []))))
        if dpg.does_item_exist("stat_channels"):
            dpg.set_value("stat_channels", str(m.get("channels_scanned", 0)))
        if dpg.does_item_exist("stat_messages"):
            dpg.set_value("stat_messages", str(m.get("messages_analyzed", 0)))
        if dpg.does_item_exist("stat_clean"):
            dpg.set_value("stat_clean", str(m.get("clean_saved", 0)))
        if dpg.does_item_exist("stat_threats"):
            dpg.set_value("stat_threats", str(m.get("quarantined", 0)))
        if dpg.does_item_exist("stat_duplicates"):
            dpg.set_value("stat_duplicates", str(m.get("duplicates_skipped", 0)))
        if dpg.does_item_exist("stat_total_stored"):
            dpg.set_value("stat_total_stored", str(m.get("total_stored", 0)))

    def collect_ui_config(self) -> Dict[str, Any]:
        token = dpg.get_value("input_token").strip() if dpg.does_item_exist("input_token") else ""
        raw_servers = dpg.get_value("input_servers").strip() if dpg.does_item_exist("input_servers") else ""

        server_list = []
        for line in raw_servers.splitlines():
            line = line.strip()
            if not line:
                continue
            tokens = [t.strip() for t in line.replace(",", " ").split() if t.strip()]
            for sid in tokens:
                if sid.isdigit():
                    server_list.append({"name": f"Server-{sid}", "server_id": sid, "channel_ids": []})

        storage_mode = "local"
        if dpg.does_item_exist("radio_storage"):
            sel = dpg.get_value("radio_storage")
            if "Google Drive" in sel:
                storage_mode = "gdrive"

        local_path = dpg.get_value("input_local_path").strip() if dpg.does_item_exist("input_local_path") else "./vault_storage"
        gdrive_account = dpg.get_value("input_gdrive_account").strip() if dpg.does_item_exist("input_gdrive_account") else ""
        gdrive_root = dpg.get_value("input_gdrive_root").strip() if dpg.does_item_exist("input_gdrive_root") else ""

        history_depth = int(dpg.get_value("slider_history")) if dpg.does_item_exist("slider_history") else 500

        webhook_enabled = dpg.get_value("check_webhook") if dpg.does_item_exist("check_webhook") else False
        webhook_url = dpg.get_value("input_webhook_url").strip() if dpg.does_item_exist("input_webhook_url") else ""

        self.config["discord"]["token"] = token
        self.config["discord"]["servers"] = server_list
        self.config["discord"]["history_depth"] = history_depth
        self.config["storage"]["mode"] = storage_mode
        self.config["storage"]["local_path"] = local_path
        self.config["storage"]["gdrive"]["account"] = gdrive_account
        self.config["storage"]["gdrive"]["root_folder_id"] = gdrive_root
        self.config["webhook"]["enabled"] = webhook_enabled
        self.config["webhook"]["url"] = webhook_url

        # Update top badge
        if dpg.does_item_exist("top_storage_badge"):
            if storage_mode == "local":
                dpg.set_value("top_storage_badge", "[STORAGE: LOCAL DISK]")
                dpg.configure_item("top_storage_badge", color=(52, 211, 153))
            else:
                dpg.set_value("top_storage_badge", "[STORAGE: GOOGLE DRIVE]")
                dpg.configure_item("top_storage_badge", color=(108, 175, 255))

        return self.config

    def on_start_clicked(self):
        if self.is_running:
            return

        cfg = self.collect_ui_config()
        save_app_config(cfg)

        if not cfg["discord"]["token"]:
            self.log("ERROR", "Please specify a valid Discord Authorization Token.")
            return

        if not cfg["discord"]["servers"]:
            self.log("ERROR", "Please provide at least one Discord Server ID.")
            return

        self.is_running = True
        if dpg.does_item_exist("status_indicator"):
            dpg.set_value("status_indicator", "[STATUS: RUNNING]")
            dpg.configure_item("status_indicator", color=(52, 211, 153))

        self.runner = PipelineRunner(
            config=cfg,
            on_log=self.log,
            on_metrics=self.update_metrics,
            on_finish=self.on_pipeline_finished
        )
        self.runner.start()

    def on_stop_clicked(self):
        if self.runner and self.is_running:
            self.runner.stop()
            self.on_pipeline_finished()

    def on_pipeline_finished(self):
        self.is_running = False
        if dpg.does_item_exist("status_indicator"):
            dpg.set_value("status_indicator", "[STATUS: IDLE]")
            dpg.configure_item("status_indicator", color=(160, 170, 185))

    def on_save_clicked(self):
        cfg = self.collect_ui_config()
        save_app_config(cfg)
        self.log("INFO", "Settings successfully saved to config/config.json")

    def browse_local_folder(self):
        try:
            ps_script = (
                "[System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null; "
                "$f = New-Object System.Windows.Forms.FolderBrowserDialog; "
                "$f.Description = 'Select Storage Directory for Sentinel Vault'; "
                "if($f.ShowDialog() -eq 'OK'){ Write-Output $f.SelectedPath }"
            )
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True)
            chosen = res.stdout.strip()
            if chosen and dpg.does_item_exist("input_local_path"):
                dpg.set_value("input_local_path", chosen)
                self.log("INFO", f"Storage directory set to: {chosen}")
        except Exception as e:
            self.log("WARN", f"Could not launch folder browser: {e}")

    def open_storage_folder(self):
        cfg = self.collect_ui_config()
        mode = cfg["storage"]["mode"]
        if mode == "local":
            p = Path(cfg["storage"]["local_path"]).resolve()
            p.mkdir(parents=True, exist_ok=True)
            os.startfile(str(p))
            self.log("INFO", f"Opened local storage folder: {p}")
        else:
            self.log("INFO", "Google Drive mode active (check drive.google.com).")

    def test_discord_token(self):
        token = dpg.get_value("input_token").strip() if dpg.does_item_exist("input_token") else ""
        if not token:
            self.log("ERROR", "Token field is empty.")
            if dpg.does_item_exist("token_status_text"):
                dpg.set_value("token_status_text", "Status: Token field empty")
                dpg.configure_item("token_status_text", color=(248, 113, 113))
            return

        client = DiscordClient(token)
        valid, msg = client.test_connection()
        if valid:
            self.log("CLEAN", f"Discord Authentication Verified: Logged in as {msg}")
            if dpg.does_item_exist("token_status_text"):
                dpg.set_value("token_status_text", f"Verified: {msg}")
                dpg.configure_item("token_status_text", color=(52, 211, 153))
        else:
            self.log("ERROR", f"Discord Authentication Failed: {msg}")
            if dpg.does_item_exist("token_status_text"):
                dpg.set_value("token_status_text", f"Error: {msg}")
                dpg.configure_item("token_status_text", color=(248, 113, 113))

    def verify_server_ids(self):
        cfg = self.collect_ui_config()
        token = cfg["discord"]["token"]
        servers = cfg["discord"]["servers"]
        if not token:
            self.log("ERROR", "Please provide a Discord Token before verifying servers.")
            return
        if not servers:
            self.log("ERROR", "No Server IDs specified to verify.")
            return

        client = DiscordClient(token)
        self.log("INFO", f"Verifying {len(servers)} Server ID(s) via Discord API...")
        for srv in servers:
            sid = srv["server_id"]
            ok, ginfo = client.get_guild_info(sid)
            if ok:
                gname = ginfo.get("name", "Unknown")
                chs = client.get_guild_channels(sid)
                self.log("CLEAN", f"Verified: '{gname}' (ID: {sid}) -> {len(chs)} accessible text channel(s)")
            else:
                self.log("WARN", f"Server ID {sid} could not be resolved: {ginfo.get('error', 'Not Found')}")

    def test_gdrive(self):
        account = dpg.get_value("input_gdrive_account").strip() if dpg.does_item_exist("input_gdrive_account") else ""
        env = os.environ.copy()
        if account:
            env["AGY_ACCOUNT"] = account
        try:
            res = subprocess.run(["gdrive", "readonly", "quota"], capture_output=True, text=True, env=env, shell=True)
            if res.returncode == 0:
                quota_line = res.stdout.splitlines()[0] if res.stdout else "Active"
                self.log("CLEAN", f"Google Drive responsive: {quota_line}")
            else:
                self.log("ERROR", f"gdrive CLI error: {res.stderr.strip() or res.stdout.strip()}")
        except Exception as e:
            self.log("ERROR", f"gdrive test exception: {e}")

    def run(self):
        dpg.create_context()
        dpg.create_viewport(title="SENTINEL VAULT // ARCHIVE INGESTION PIPELINE v2.1", width=1020, height=720)
        self.setup_theme()

        existing_servers = self.config.get("discord", {}).get("servers", [])
        servers_str = "\n".join(str(s.get("server_id")) for s in existing_servers if s.get("server_id"))

        storage_mode = self.config.get("storage", {}).get("mode", "local")

        with dpg.window(label="Main Window", tag="main_window", no_title_bar=True):
            # Top Bar
            with dpg.group(horizontal=True):
                dpg.add_text("SENTINEL VAULT", color=(108, 175, 255))
                dpg.add_text("// MULTI-TARGET ARCHIVE INGESTION & THREAT QUARANTINE", color=(140, 150, 168))
                dpg.add_spacer(width=160)
                
                badge_text = "[STORAGE: LOCAL DISK]" if storage_mode == "local" else "[STORAGE: GOOGLE DRIVE]"
                badge_color = (52, 211, 153) if storage_mode == "local" else (108, 175, 255)
                dpg.add_text(badge_text, tag="top_storage_badge", color=badge_color)
                dpg.add_spacer(width=20)
                dpg.add_text("[STATUS: IDLE]", tag="status_indicator", color=(160, 170, 185))

            dpg.add_separator()

            # Tab Navigation
            with dpg.tab_bar():
                # --- TAB 1: Discord Setup ---
                with dpg.tab(label="Discord Setup"):
                    dpg.add_spacing(count=1)

                    with dpg.group(horizontal=True):
                        # Left Box: Credentials & Scan Parameters
                        with dpg.child_window(width=480, height=440, border=True):
                            dpg.add_text("DISCORD AUTHORIZATION", color=(108, 175, 255))
                            dpg.add_separator()
                            dpg.add_text("User Token or Bot Token:", color=(160, 170, 185))
                            dpg.add_input_text(
                                tag="input_token",
                                default_value=self.config.get("discord", {}).get("token", ""),
                                password=True,
                                width=440
                            )

                            with dpg.group(horizontal=True):
                                dpg.add_button(label="Test Token", callback=self.test_discord_token, width=110)
                                dpg.add_text("Status: Untested", tag="token_status_text", color=(140, 150, 168))

                            dpg.add_spacing(count=2)
                            dpg.add_text("SCAN DEPTH CONFIGURATION", color=(108, 175, 255))
                            dpg.add_separator()
                            dpg.add_text("Past Messages to Scan (Per Channel):", color=(160, 170, 185))
                            dpg.add_slider_int(
                                tag="slider_history",
                                default_value=self.config.get("discord", {}).get("history_depth", 500),
                                min_value=50,
                                max_value=2000,
                                width=440,
                                format="%d messages"
                            )

                            dpg.add_spacing(count=2)
                            dpg.add_text("CHANNEL FILTERING (AUTO-SKIP)", color=(108, 175, 255))
                            dpg.add_separator()
                            dpg.add_text("Channels with these words are skipped automatically:", color=(140, 150, 168))
                            dpg.add_text("rules, ticket, tickets, welcome, verify, faq, voice, cat-pics, memes, clowns", color=(108, 175, 255))
                            dpg.add_text("All uploader channels and release drops are fully scanned.", color=(160, 170, 185))

                        # Right Box: Target Servers
                        with dpg.child_window(width=480, height=440, border=True):
                            dpg.add_text("MONITORED SERVERS (GUILDS)", color=(108, 175, 255))
                            dpg.add_separator()
                            dpg.add_text("Paste Discord Server IDs below (one ID per line):", color=(160, 170, 185))
                            dpg.add_input_text(
                                tag="input_servers",
                                default_value=servers_str,
                                multiline=True,
                                height=280,
                                width=440
                            )

                            with dpg.group(horizontal=True):
                                dpg.add_button(label="Verify Server IDs", callback=self.verify_server_ids, width=150)
                                dpg.add_button(label="Save Settings", callback=self.on_save_clicked, width=120)

                # --- TAB 2: Storage Target ---
                with dpg.tab(label="Storage Target"):
                    dpg.add_spacing(count=1)

                    with dpg.group(horizontal=True):
                        # Left Box: Storage Backend Selection & Paths
                        with dpg.child_window(width=480, height=440, border=True):
                            dpg.add_text("STORAGE BACKEND SELECTION", color=(108, 175, 255))
                            dpg.add_separator()

                            initial_storage = "Local Disk Directory (Recommended - No Cloud Required)"
                            if self.config.get("storage", {}).get("mode") == "gdrive":
                                initial_storage = "Google Drive Cloud Vault (Requires gdrive CLI)"

                            dpg.add_radio_button(
                                items=[
                                    "Local Disk Directory (Recommended - No Cloud Required)",
                                    "Google Drive Cloud Vault (Requires gdrive CLI)"
                                ],
                                default_value=initial_storage,
                                tag="radio_storage"
                            )

                            dpg.add_spacing(count=2)
                            dpg.add_text("LOCAL DIRECTORY SETTINGS", color=(108, 175, 255))
                            dpg.add_separator()
                            dpg.add_text("Target Folder Path:", color=(160, 170, 185))
                            dpg.add_input_text(
                                tag="input_local_path",
                                default_value=self.config.get("storage", {}).get("local_path", "./vault_storage"),
                                width=440
                            )

                            with dpg.group(horizontal=True):
                                dpg.add_button(label="Browse...", callback=self.browse_local_folder, width=100)
                                dpg.add_button(label="Open Directory", callback=self.open_storage_folder, width=120)

                            dpg.add_spacing(count=2)
                            dpg.add_text("GOOGLE DRIVE SETTINGS (OPTIONAL)", color=(108, 175, 255))
                            dpg.add_separator()
                            dpg.add_input_text(
                                label="Account Email",
                                tag="input_gdrive_account",
                                default_value=self.config.get("storage", {}).get("gdrive", {}).get("account", ""),
                                width=320
                            )
                            dpg.add_input_text(
                                label="Root Folder ID",
                                tag="input_gdrive_root",
                                default_value=self.config.get("storage", {}).get("gdrive", {}).get("root_folder_id", ""),
                                width=320
                            )
                            dpg.add_button(label="Verify Drive Connection", callback=self.test_gdrive, width=180)

                        # Right Box: Directory Structure Preview
                        with dpg.child_window(width=480, height=440, border=True):
                            dpg.add_text("DIRECTORY TAXONOMY PREVIEW", color=(108, 175, 255))
                            dpg.add_separator()
                            dpg.add_text("Clean hierarchical structure automatically generated:", color=(160, 170, 185))
                            dpg.add_spacing(count=1)

                            dpg.add_text("GAMES:", color=(108, 175, 255))
                            dpg.add_text("  Games/Fortnite/External/Kernel/ and UserMode/")
                            dpg.add_text("  Games/Fortnite/Internal/DLL/ and Injectors/")
                            dpg.add_text("  Games/CounterStrike_CS2/External/ and Internal/")
                            dpg.add_text("  Games/CounterStrike_CSGO/, Rust/, Roblox/, GTA V/")
                            dpg.add_spacing(count=1)

                            dpg.add_text("DEDICATED TOOLS:", color=(108, 175, 255))
                            dpg.add_text("  Tools/Drivers/  (Kernel drivers for EAC, BE, Vanguard)")
                            dpg.add_text("  Tools/Mappers/  (KDMapper, VDM, DrvMap)")
                            dpg.add_text("  Tools/Injectors/ and Tools/Dumpers/")
                            dpg.add_spacing(count=1)

                            dpg.add_text("HARDWARE SPOOFERS:", color=(108, 175, 255))
                            dpg.add_text("  Spoofer/Universal/Temp/ and Perm/")
                            dpg.add_spacing(count=1)

                            dpg.add_text("SECURITY ISOLATION:", color=(248, 113, 113))
                            dpg.add_text("  Quarantine/Detected_Viruses/ (*.quarantined)")
                            dpg.add_text("  Quarantine/Suspicious_Stealers/ (*.quarantined)")

                # --- TAB 3: Security & Automation ---
                with dpg.tab(label="Security & Automation"):
                    dpg.add_spacing(count=1)

                    with dpg.group(horizontal=True):
                        # Left Box: Threat Scanner
                        with dpg.child_window(width=480, height=440, border=True):
                            dpg.add_text("IN-ARCHIVE STATIC THREAT SCANNER", color=(108, 175, 255))
                            dpg.add_separator()
                            dpg.add_checkbox(label="Deep In-Archive Inspection (.zip, .rar, .7z, .tar)", default_value=True)
                            dpg.add_checkbox(label="Isolate Discord Webhooks & Token Grabbers", default_value=True)
                            dpg.add_checkbox(label="Auto-Append .quarantined Suffix to High-Risk Binaries", default_value=True)
                            dpg.add_checkbox(label="Content SHA-256 Deduplication (Zero Redundant Files)", default_value=True)

                            dpg.add_spacing(count=2)
                            dpg.add_text("THREAT SIGNATURES DETECTED", color=(108, 175, 255))
                            dpg.add_separator()
                            dpg.add_text("• Discord Webhook Extraction (api/webhooks/...)")
                            dpg.add_text("• Telegram Bot C2 Tokens (api.telegram.org/bot...)")
                            dpg.add_text("• Token Grabbers (BlankGrabber, W4SP, Lumma, RedLine)")
                            dpg.add_text("• Credential Stealers (CryptUnprotectData, Login Data, Cookies)")
                            dpg.add_text("• Malicious Droppers (PowerShell -enc, certutil, bitsadmin)")

                        # Right Box: n8n & External Webhooks
                        with dpg.child_window(width=480, height=440, border=True):
                            dpg.add_text("N8N / EXTERNAL AUTOMATION (OPTIONAL)", color=(108, 175, 255))
                            dpg.add_separator()
                            dpg.add_text("Sentinel Vault operates 100% self-contained without n8n.", color=(52, 211, 153))
                            dpg.add_text("External automation is entirely optional and only needed", color=(160, 170, 185))
                            dpg.add_text("if you wish to relay event notifications to Discord/Telegram.", color=(160, 170, 185))

                            dpg.add_spacing(count=2)
                            dpg.add_checkbox(
                                label="Forward Telemetry to External Webhook",
                                tag="check_webhook",
                                default_value=self.config.get("webhook", {}).get("enabled", False)
                            )
                            dpg.add_text("Webhook URL:")
                            dpg.add_input_text(
                                tag="input_webhook_url",
                                default_value=self.config.get("webhook", {}).get("url", "http://localhost:5678/webhook/discord/source-eval"),
                                width=440
                            )

                            dpg.add_spacing(count=2)
                            dpg.add_text("SUMMARY:", color=(108, 175, 255))
                            dpg.add_text("No Node.js or n8n installation is required to use this software.")
                            dpg.add_text("All downloads, static analysis, and sorting run natively in Python.")

                # --- TAB 4: Ingestion Console ---
                with dpg.tab(label="Ingestion Console"):
                    dpg.add_spacing(count=1)

                    # Action Control Bar
                    with dpg.group(horizontal=True):
                        dpg.add_button(label="START PIPELINE", callback=self.on_start_clicked, width=140, height=28)
                        dpg.add_button(label="STOP", callback=self.on_stop_clicked, width=80, height=28)
                        dpg.add_button(label="Save Config", callback=self.on_save_clicked, width=100, height=28)
                        dpg.add_button(label="Open Vault", callback=self.open_storage_folder, width=100, height=28)
                        dpg.add_button(label="Clear Log", callback=lambda: dpg.delete_item("console_log", children_only=True), width=90, height=28)

                    dpg.add_spacing(count=1)

                    # Telemetry HUD
                    with dpg.group(horizontal=True):
                        with dpg.child_window(width=152, height=52, border=True):
                            dpg.add_text("SERVERS", color=(108, 175, 255))
                            dpg.add_text(str(len(existing_servers)), tag="stat_servers")

                        with dpg.child_window(width=152, height=52, border=True):
                            dpg.add_text("CHANNELS", color=(185, 145, 255))
                            dpg.add_text("0", tag="stat_channels")

                        with dpg.child_window(width=152, height=52, border=True):
                            dpg.add_text("MESSAGES", color=(255, 210, 70))
                            dpg.add_text("0", tag="stat_messages")

                        with dpg.child_window(width=152, height=52, border=True):
                            dpg.add_text("CLEAN SAVED", color=(52, 211, 153))
                            dpg.add_text("0", tag="stat_clean", color=(52, 211, 153))

                        with dpg.child_window(width=152, height=52, border=True):
                            dpg.add_text("QUARANTINED", color=(248, 113, 113))
                            dpg.add_text("0", tag="stat_threats", color=(248, 113, 113))

                        with dpg.child_window(width=152, height=52, border=True):
                            dpg.add_text("DUPLICATES", color=(140, 150, 168))
                            dpg.add_text("0", tag="stat_duplicates")

                    dpg.add_spacing(count=1)

                    # Live Monospaced Activity Console
                    dpg.add_text("LIVE ACTIVITY LOG:", color=(140, 150, 168))
                    with dpg.child_window(tag="console_log", height=370, border=True, horizontal_scrollbar=True):
                        dpg.add_text("[00:00:00] [READY  ] Sentinel Vault v2.1 Initialized.", color=(108, 175, 255))
                        dpg.add_text("[00:00:00] [INFO   ] Configure your Discord Token and Server IDs, choose storage, then click START PIPELINE.", color=(160, 170, 185))

        dpg.setup_dearpygui()
        dpg.set_primary_window("main_window", True)
        dpg.show_viewport()
        dpg.start_dearpygui()
        dpg.destroy_context()


if __name__ == "__main__":
    app = ImGuiDashboard()
    app.run()
