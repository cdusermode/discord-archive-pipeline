"""
Triage Engine: Multi-Game Source Evaluation & Security Isolation.
Features:
- Seamless integration with AIClassifier (Gemini / OpenAI / Ollama)
- Deep code & binary signature analysis (DriverEntry, kdmapper, CreateRemoteThread, offsets)
- Clean directory routing:
  - Games/Fortnite/External/Kernel, Games/Fortnite/External/UserMode, Games/Fortnite/Internal/DLL, Games/Fortnite/Internal/Injectors
  - Tools/Drivers/ (Kernel drivers for EAC, BattlEye, Vanguard, General)
  - Tools/Mappers/ (KDMapper, VDM, DrvMap, General)
  - Tools/Injectors/
  - Tools/Dumpers/
  - Spoofer/Universal/ (Temp / Perm)
  - Quarantine/Detected_Viruses/, Quarantine/Suspicious_Stealers/ (*.quarantined)
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional

from core.security_scanner import SecurityScanner

# --- Configuration & Rules Matrix ---

GAME_RULES = {
    "Fortnite": {
        "engine": "UE 5.4+",
        "ac_tier": "Tier 1",
        "max_offset_days": 90,
        "keywords": ["fortnite", "fn", "chapter 5", "chapter 6", "unreal 5", "ue5", "crisis", "slotted", "proswapper", "galaxy", "uworld", "gnames", "fortpawn"]
    },
    "CounterStrike_CS2": {
        "engine": "Source 2",
        "ac_tier": "Tier 2",
        "max_offset_days": 60,
        "keywords": ["cs2", "counterstrike2", "counter-strike 2", "source 2", "client.dll", "schema", "vacnet", "cs2-external", "source2gen", "larpware_cs2", "cs2-internal", "dwlocalplayerpawn", "dwentitylist"]
    },
    "CounterStrike_CSGO": {
        "engine": "Source 1",
        "ac_tier": "Legacy",
        "max_offset_days": None,
        "keywords": ["csgo", "cs:go", "counter-strike global offensive", "source 1", "source1", "velocity", "osiris", "aimtux", "csgo-simple", "csgosimple", "gladiatorcheatz", "fuzion", "weave", "pandora", "onetap", "gamesense", "dwclientstate"]
    },
    "Rust": {
        "engine": "Unity",
        "ac_tier": "Tier 1",
        "max_offset_days": 60,
        "keywords": ["rust", "facepunch", "cloak-rust", "rust-external", "rustclient", "eac rust", "baseplayer", "basenetworkable"]
    },
    "Roblox": {
        "engine": "Roblox",
        "ac_tier": "Tier 2",
        "max_offset_days": None,
        "keywords": ["roblox", "fflag", "fflag_dumper", "rbx", "robloxplayerbeta"]
    },
    "Grand_Theft_Auto_V": {
        "engine": "RAGE",
        "ac_tier": "Tier 3",
        "max_offset_days": None,
        "keywords": ["gta5", "gtav", "gta v", "fivem", "rockstar", "gosth_fivem", "citizenfx"]
    },
    "Rainbow_Six_Siege": {
        "engine": "AnvilNext",
        "ac_tier": "Tier 1",
        "max_offset_days": 60,
        "keywords": ["r6", "r6s", "rainbow six", "siege", "ubisoft", "ubisoft_src"]
    },
    "Blood_Strike": {
        "engine": "Unity",
        "ac_tier": "Tier 3",
        "max_offset_days": 60,
        "keywords": ["blood strike", "bloodstrike", "bloodstrikepy"]
    },
    "Unturned": {
        "engine": "Unity",
        "ac_tier": "Tier 3",
        "max_offset_days": None,
        "keywords": ["unturned", "unturned_internal"]
    },
    "Minecraft_Java": {
        "engine": "JVM",
        "ac_tier": "Versioned",
        "max_offset_days": None,
        "keywords": ["minecraft java", "fabric", "forge", "mixin", "alienclient", "1.8.9", "1.20", "1.21", "jvm", "entityplayersp"]
    },
    "Minecraft_Bedrock": {
        "engine": "C++ / UWP",
        "ac_tier": "Versioned",
        "max_offset_days": None,
        "keywords": ["minecraft bedrock", "win10 edition", "minecraft uwp", "bedrock"]
    },
    "Bodycam": {
        "engine": "UE 5 Indie",
        "ac_tier": "Indie",
        "max_offset_days": None,
        "keywords": ["bodycam", "reissad"]
    },
    "The_Finals": {
        "engine": "UE 5.3",
        "ac_tier": "Tier 1",
        "max_offset_days": 90,
        "keywords": ["the finals", "embark", "finals"]
    }
}

SPOOFER_PROFILES = {
    "EAC_BattlEye": ["eac", "easyanticheat", "battleye", "be spoofer", "fortnite spoofer"],
    "Ricochet": ["ricochet", "cod spoofer", "warzone spoofer", "tpm", "pcr"],
    "Vanguard": ["vanguard", "vg", "valorant spoofer", "hypervisor", "nvram"],
    "Universal": ["universal", "hwid", "serial", "mac", "volumeid", "guid", "spoofer", "null-spoofer"]
}


class TriageEngine:
    def __init__(self):
        self.scanner = SecurityScanner()

    def scan_for_malware(self, text_content: str, raw_bytes: bytes = b"") -> Tuple[str, List[str]]:
        threats = []
        if text_content:
            threats.extend(self.scanner.scan_text_content(text_content))
        if raw_bytes:
            threats.extend(self.scanner.scan_file_bytes(raw_bytes, "binary"))

        if threats:
            status = "QUARANTINE_VIRUS" if any("Dropper" in t or "Malicious" in t or "High-Risk" in t for t in threats) else "SUSPICIOUS_STEALER"
            return status, threats

        return "CLEAN", []

    def classify_spoofer(self, content: str) -> Optional[Dict[str, str]]:
        lower = content.lower()
        if not any(k in lower for k in ["spoofer", "hwid", "serial changer", "cleaner", "null-spoofer"]):
            return None

        matched_target = "Universal"
        for target, kws in SPOOFER_PROFILES.items():
            if any(k in lower for k in kws):
                matched_target = target
                break

        persistence = "Temp"
        if any(k in lower for k in ["perm", "permanent", "nvram", "flash", "bios", "efi", "dmi write"]):
            persistence = "Perm"
        elif any(k in lower for k in ["semi-perm", "semiperm", "registry write", "persist"]):
            persistence = "SemiPerm"

        return {
            "target": matched_target,
            "persistence": persistence
        }

    def classify_tool_or_cheat(self, content: str, namelist: Optional[List[str]] = None) -> Tuple[str, str, str, str]:
        """
        Classifies content and archive file tree into: (target_game, category, target_folder, subtype)
        """
        lower = content.lower()
        files = [f.lower() for f in (namelist or [])]
        all_text = lower + " " + " ".join(files)

        # 1. Detect Game Target
        matched_game = "Other"
        for game_id, rules in GAME_RULES.items():
            if any(k in all_text for k in rules["keywords"]):
                matched_game = game_id
                break

        # 2. Check for Independent Tools / Mappers / Drivers
        has_sys_file = any(f.endswith(".sys") for f in files)
        is_mapper = any(k in all_text for k in ["mapper", "kdmapper", "vdm", "drvmap", "kdu", "superultraamazingtungtungmapper", "map driver", "iqvw64e"])
        is_driver = (has_sys_file or any(k in all_text for k in ["driver", "driverentry", "iocreatedevice", "byovd", "kernel driver", "kernel-driver", "rootkit"])) and not is_mapper
        is_injector = any(k in all_text for k in ["injector", "inject", "manualmap", "dll_injector", "createremotethread", "loader_for_developer", "injc"])
        is_dumper = any(k in all_text for k in ["dumper", "dumpspace", "uedumper", "source2gen", "cs2dumper", "il2cppdumper"])
        is_re = any(k in all_text for k in ["ida-pro", "idapro", "ghidra", "gamehackingacademy", "valveresourceformat", "imrefl", "luckywarereverse"])
        is_gui = any(k in all_text for k in ["fgui", "zgui", "nuklear", "imgui-menu", "imgui-base", "imgui"])
        is_auth = any(k in all_text for k in ["cpp-auth", "unkauthproject", "keyauth", "auth-system"])

        # Dedicated Tools routing (Drivers & Mappers belong in Tools)
        if is_mapper:
            return matched_game, "Tools", "Tools/Mappers/", "Mappers"
        if is_driver:
            return matched_game, "Tools", "Tools/Drivers/", "Drivers"
        if is_injector:
            if matched_game != "Other":
                return matched_game, "Game_Internal", f"Games/{matched_game}/Internal/Injectors/", "Injectors"
            return "Other", "Tools", "Tools/Injectors/", "Injectors"
        if is_dumper:
            if matched_game != "Other":
                return matched_game, "Game_Tools", f"Games/{matched_game}/Tools/Dumpers/", "Dumpers"
            return "Other", "Tools", "Tools/Dumpers/", "Dumpers"
        if is_re:
            return "Other", "Tools", "Tools/Reverse_Engineering/", "Reverse_Engineering"
        if is_gui:
            return "Other", "Tools", "Tools/GUI_Frameworks/", "GUI_Frameworks"
        if is_auth:
            return "Other", "Tools", "Tools/Auth_Systems/", "Auth_Systems"

        # 3. Game Cheat Architecture: Kernel vs UserMode / Internal vs External
        has_dll_file = any(f.endswith(".dll") for f in files)
        is_internal = has_dll_file or any(k in all_text for k in ["internal", "vmt", "hook", "minhook", "dllmain", "kiero", "present hook"])
        is_kernel = any(k in all_text for k in ["kernel", "ioctl", "physicalmemory", "byovd", "vmm", "dma", "cr3", "rwmem"])
        is_usermode = any(k in all_text for k in ["overlay", "esp", "aimbot", "radar", "pixel", "yolo", "usermode", "user mode", "external"])

        if matched_game != "Other":
            if is_internal:
                return matched_game, "Cheat", f"Games/{matched_game}/Internal/DLL/", "Internal_DLL"
            elif is_kernel:
                return matched_game, "Cheat", f"Games/{matched_game}/External/Kernel/", "External_Kernel"
            else:
                return matched_game, "Cheat", f"Games/{matched_game}/External/UserMode/", "External_UserMode"

        # 4. Generic / Non-Game Cheats
        if is_internal:
            return "Other", "Cheat", "Other/Cheats/Internal/DLL/", "Internal_DLL"
        elif is_kernel:
            return "Other", "Cheat", "Other/Cheats/External/Kernel/", "External_Kernel"
        elif is_usermode:
            return "Other", "Cheat", "Other/Cheats/External/UserMode/", "External_UserMode"

        return "Other", "Utility", "Other/Utilities/", "General_Utility"

    def evaluate(
        self,
        payload: Dict[str, Any],
        raw_bytes: bytes = b"",
        namelist: Optional[List[str]] = None,
        ai_decision: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        content = payload.get("content", "")
        post_timestamp = payload.get("timestamp", datetime.now(timezone.utc).isoformat())

        sec_status, threats = self.scan_for_malware(content, raw_bytes)
        spoofer_info = self.classify_spoofer(content)

        # 1. Check Threat Quarantine First (Zero-Tolerance)
        if sec_status in ("QUARANTINE_VIRUS", "SUSPICIOUS_STEALER"):
            action = "DOWNLOAD_QUARANTINE"
            dest_folder = f"Quarantine/{'Detected_Viruses' if sec_status == 'QUARANTINE_VIRUS' else 'Suspicious_Stealers'}/"
            game_id = "Threat_Quarantined"
            category = "Quarantine"
            subtype = sec_status

        # 2. Check Spoofer
        elif spoofer_info:
            action = "DOWNLOAD_CLEAN"
            dest_folder = f"Spoofer/{spoofer_info['target']}/{spoofer_info['persistence']}/"
            game_id = "Universal"
            category = "Spoofer"
            subtype = spoofer_info['persistence']

        # 3. AI Classifier Decision (If enabled and confident)
        elif ai_decision and ai_decision.get("destination_folder") and ai_decision.get("confidence", 0) >= 0.7:
            action = "DOWNLOAD_CLEAN"
            dest_folder = ai_decision.get("destination_folder")
            game_id = ai_decision.get("target_game", "Other")
            category = ai_decision.get("category", "Tools")
            subtype = "AI_Classified"

        # 4. Deep Heuristic & Code Signature Analyzer
        else:
            action = "DOWNLOAD_CLEAN"
            game_id, category, target_folder, subtype = self.classify_tool_or_cheat(content, namelist)
            dest_folder = target_folder

        metadata = {
            "asset_id": f"{game_id[:6].upper()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_game": game_id,
            "category": category,
            "subtype": subtype,
            "spoofer": spoofer_info,
            "ai_decision": ai_decision,
            "security": {
                "status": sec_status,
                "threats": threats
            },
            "decision": {
                "action": action,
                "destination_folder": dest_folder
            },
            "source_origin": {
                "server": payload.get("server_name"),
                "channel": payload.get("channel_name"),
                "author": payload.get("author_name"),
                "message_id": payload.get("message_id")
            }
        }

        return metadata
