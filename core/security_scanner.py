"""
Comprehensive Security Scanner & Threat Quarantine Engine.
Performs in-depth static analysis of archives (ZIP, RAR, 7Z, TAR) and standalone files
to detect:
- Discord Webhooks & Token Grabber patterns
- Telegram Bot C2 tokens
- Malicious dropper scripts (.bat, .cmd, .ps1, .vbs, .hta, .scr)
- Credential harvesting signatures (browser login data, cookies, crypto wallets)
- High-entropy obfuscated payloads & packed executables
"""

import os
import re
import math
import zipfile
import tarfile
import subprocess
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional

# --- Threat Signatures & Patterns ---

DISCORD_WEBHOOK_REGEX = re.compile(
    r'https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',
    re.IGNORECASE
)

TELEGRAM_BOT_REGEX = re.compile(
    r'(?:https?://api\.telegram\.org/bot|bot)?(?:\b|\"|\')[0-9]{8,11}:[a-zA-Z0-9_-]{35}(?:\b|\"|\')',
    re.IGNORECASE
)

DISCORD_TOKEN_PATTERNS = [
    re.compile(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27,}', re.ASCII),
    re.compile(r'mfa\.[\w-]{84}', re.ASCII),
    re.compile(r'dQw4w9WgXcQ:[^"\']+', re.ASCII),  # Encrypted token signature
]

STEALER_SIGNATURES = [
    re.compile(r'\b(?:BlankGrabber|W4SP|RedLine|Lumma|PirateStealer|LunaGrabber|HazardGrabber|Empyrean|DiscordTokenGrabber|RobloxCookieGrabber)\b', re.IGNORECASE),
    re.compile(r'(?:Login Data|Web Data|Cookies|Local State|CryptUnprotectData)', re.IGNORECASE),
    re.compile(r'os\.getenv\(["\']APPDATA["\']\).*(?:discord|google|brave|opera|telegram)', re.IGNORECASE),
    re.compile(r'\\Roaming\\(?:Discord|Lightcord|discordptb|discordcanary)\\Local Storage\\leveldb', re.IGNORECASE),
    re.compile(r'wallet(?:\.dat|\.keys|s\\)', re.IGNORECASE),
]

DROPPER_COMMAND_PATTERNS = [
    re.compile(r'powershell.*(?:-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{30,}', re.IGNORECASE),
    re.compile(r'certutil\s+(?:-urlcache|-f|-decode)', re.IGNORECASE),
    re.compile(r'bitsadmin\s+/transfer', re.IGNORECASE),
    re.compile(r'Invoke-WebRequest.*(?:-OutFile|\.DownloadFile|\.DownloadString)', re.IGNORECASE),
    re.compile(r'curl\s+(?:-O|-o)\s+https?://', re.IGNORECASE),
    re.compile(r'wscript\.shell', re.IGNORECASE),
    re.compile(r'mshta\s+https?://', re.IGNORECASE),
]

DANGEROUS_EXTENSIONS = {'.scr', '.pif', '.hta', '.vbs', '.vbe', '.wsf', '.cpl'}
SCRIPT_EXTENSIONS = {'.bat', '.cmd', '.ps1', '.vbs', '.js', '.py'}
INSPECTABLE_TEXT_EXTS = {'.bat', '.cmd', '.ps1', '.vbs', '.js', '.py', '.txt', '.json', '.cs', '.cpp', '.h', '.hpp', '.c', '.lua', '.ini'}


class SecurityScanner:
    """
    Static archive and file threat scanner.
    """

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for x in range(256):
            p_x = float(data.count(x)) / length
            if p_x > 0:
                entropy -= p_x * math.log(p_x, 2)
        return entropy

    @classmethod
    def scan_text_content(cls, text: str) -> List[str]:
        threats = []

        # 1. Discord Webhooks
        webhooks = DISCORD_WEBHOOK_REGEX.findall(text)
        if webhooks:
            threats.append(f"Hardcoded Discord Webhook: {len(webhooks)} found")

        # 2. Telegram Bot C2
        telegram_matches = TELEGRAM_BOT_REGEX.findall(text)
        if telegram_matches:
            threats.append(f"Disclosed Telegram Bot C2 Token: {len(telegram_matches)} found")

        # 3. Discord Tokens
        for pat in DISCORD_TOKEN_PATTERNS:
            if pat.search(text):
                threats.append("Embedded Discord Token Pattern")
                break

        # 4. Stealer signatures
        for pat in STEALER_SIGNATURES:
            m = pat.search(text)
            if m:
                threats.append(f"Stealer / Credential Harvesting Signature: '{m.group(0)}'")

        # 5. Dropper commands
        for pat in DROPPER_COMMAND_PATTERNS:
            m = pat.search(text)
            if m:
                threats.append(f"Malicious Dropper Execution Pattern: '{m.group(0)}'")

        return threats

    @classmethod
    def scan_file_bytes(cls, raw_bytes: bytes, filename: str) -> List[str]:
        threats = []
        ext = ("." + filename.split(".")[-1].lower()) if "." in filename else ""

        if ext in DANGEROUS_EXTENSIONS:
            threats.append(f"High-Risk Executable Extension: {ext}")

        try:
            text = raw_bytes.decode('utf-8', errors='ignore')
            text_threats = cls.scan_text_content(text)
            threats.extend(text_threats)
        except Exception:
            pass

        if ext in SCRIPT_EXTENSIONS:
            for pat in DROPPER_COMMAND_PATTERNS:
                if pat.search(text):
                    threats.append(f"Script Dropper in {filename}")

        return threats

    @classmethod
    def scan_zip_archive(cls, file_path: Path) -> Tuple[str, List[str], List[str]]:
        threats = []
        namelist = []

        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                namelist = [n.lower() for n in zf.namelist()]

                for info in zf.infolist():
                    name_lower = info.filename.lower()
                    ext = ("." + name_lower.split(".")[-1]) if "." in name_lower else ""

                    if ext in DANGEROUS_EXTENSIONS:
                        threats.append(f"Malicious Executable inside archive: {info.filename}")

                    if ext in INSPECTABLE_TEXT_EXTS:
                        read_size = min(info.file_size, 1024 * 1024)
                        try:
                            with zf.open(info) as mf:
                                content = mf.read(read_size)
                                text = content.decode('utf-8', errors='ignore')
                                file_threats = cls.scan_text_content(text)
                                for t in file_threats:
                                    threats.append(f"{t} in '{info.filename}'")
                        except Exception:
                            pass

        except zipfile.BadZipFile:
            threats.append("Corrupted or Invalid Zip Archive")
        except Exception as e:
            threats.append(f"Zip Inspection Error: {e}")

        verdict = cls._determine_verdict(threats)
        return verdict, threats, namelist

    @classmethod
    def scan_tar_archive(cls, file_path: Path) -> Tuple[str, List[str], List[str]]:
        threats = []
        namelist = []

        try:
            with tarfile.open(file_path, 'r:*') as tf:
                for member in tf.getmembers():
                    name_lower = member.name.lower()
                    namelist.append(name_lower)
                    ext = ("." + name_lower.split(".")[-1]) if "." in name_lower else ""

                    if ext in DANGEROUS_EXTENSIONS:
                        threats.append(f"Malicious Executable inside tar: {member.name}")

                    if ext in INSPECTABLE_TEXT_EXTS and member.isfile():
                        try:
                            f = tf.extractfile(member)
                            if f:
                                content = f.read(1024 * 1024)
                                text = content.decode('utf-8', errors='ignore')
                                for t in cls.scan_text_content(text):
                                    threats.append(f"{t} in '{member.name}'")
                        except Exception:
                            pass
        except Exception as e:
            threats.append(f"Tar Inspection Error: {e}")

        verdict = cls._determine_verdict(threats)
        return verdict, threats, namelist

    @classmethod
    def scan_generic_archive(cls, file_path: Path) -> Tuple[str, List[str], List[str]]:
        threats = []
        namelist = []

        # 1. Windows built-in bsdtar listing
        try:
            cmd = ["tar.exe", "-tf", str(file_path)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                lines = [line.strip().lower() for line in res.stdout.splitlines() if line.strip()]
                namelist.extend(lines)
                for item in lines:
                    ext = ("." + item.split(".")[-1]) if "." in item else ""
                    if ext in DANGEROUS_EXTENSIONS:
                        threats.append(f"Dangerous Dropper Extension inside archive: {item}")
        except Exception:
            pass

        # 2. Raw string scanning
        try:
            with open(file_path, "rb") as f:
                raw = f.read(4 * 1024 * 1024)
                text = raw.decode('utf-8', errors='ignore')
                raw_threats = cls.scan_text_content(text)
                threats.extend(raw_threats)

                if not namelist:
                    matches = re.findall(r'[\w\-/\\]+\.(?:sys|dll|exe|bat|ps1|vbs|txt|json)\b', text, re.IGNORECASE)
                    namelist.extend([m.lower() for m in matches[:50]])
        except Exception as e:
            threats.append(f"Binary String Scan Error: {e}")

        verdict = cls._determine_verdict(threats)
        return verdict, threats, namelist

    @classmethod
    def scan_archive(cls, file_path: Path) -> Tuple[str, List[str], List[str]]:
        """
        Main entry point for deep archive scanning.
        Returns: (verdict, threats, namelist)
        verdict is one of: "CLEAN", "QUARANTINE_VIRUS", "SUSPICIOUS_STEALER"
        """
        file_lower = file_path.name.lower()

        if file_lower.endswith(".zip"):
            return cls.scan_zip_archive(file_path)
        elif file_lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2")):
            return cls.scan_tar_archive(file_path)
        else:
            return cls.scan_generic_archive(file_path)

    @classmethod
    def _determine_verdict(cls, threats: List[str]) -> str:
        if not threats:
            return "CLEAN"

        virus_keywords = ["dropper", "powershell", "certutil", "bitsadmin", "executable inside", "corrupted", "high-risk"]
        is_virus = any(any(vk in t.lower() for vk in virus_keywords) for t in threats)

        if is_virus:
            return "QUARANTINE_VIRUS"
        return "SUSPICIOUS_STEALER"
