"""
Unified Storage Manager: Dual Backend (Local Disk Storage OR Google Drive Cloud).
Manages file persistence, directory provisioning, SHA-256 deduplication,
and transaction ledger synchronization.
"""

import os
import json
import shutil
import hashlib
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List


class StorageMode:
    LOCAL = "local"
    GDRIVE = "gdrive"


class StorageManager:
    """
    Handles file storage across Local Disk or Google Drive.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get("storage", {})
        self.mode = self.config.get("mode", StorageMode.LOCAL)
        self.local_root = Path(self.config.get("local_path", "./vault_storage")).resolve()

        # Google Drive settings
        gdrive_cfg = self.config.get("gdrive", {})
        self.gdrive_account = gdrive_cfg.get("account", "").strip()
        self.gdrive_root_id = gdrive_cfg.get("root_folder_id", "").strip()

        # Ledger path
        if self.mode == StorageMode.LOCAL:
            self.local_root.mkdir(parents=True, exist_ok=True)
            self.ledger_path = self.local_root / "vault_ledger.json"
        else:
            self.ledger_path = Path("./vault_ledger.json").resolve()

        self.ledger = self._load_ledger()
        self.folder_cache = {}

    def _load_ledger(self) -> Dict[str, Any]:
        if self.ledger_path.exists():
            try:
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "processed_urls": [],
            "processed_hashes": [],
            "records": []
        }

    def _save_ledger(self):
        try:
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.ledger_path, "w", encoding="utf-8") as f:
                json.dump(self.ledger, f, indent=2)
        except Exception as e:
            print(f"[Storage] Warning: Failed to write ledger: {e}")

    def is_url_processed(self, url: str) -> bool:
        if not url:
            return False
        return url in self.ledger.get("processed_urls", [])

    def is_hash_processed(self, file_hash: str) -> bool:
        if not file_hash:
            return False
        return file_hash in self.ledger.get("processed_hashes", [])

    def calculate_sha256(self, file_path: Path) -> str:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def store_file(
        self,
        source_path: Path,
        destination_subpath: str,
        filename: str,
        url: str = "",
        verdict: str = "CLEAN",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Stores file to either local disk or Google Drive based on active mode.
        """
        if not source_path.exists():
            raise FileNotFoundError(f"Source file does not exist: {source_path}")

        file_hash = self.calculate_sha256(source_path)
        file_size = source_path.stat().st_size

        # Check content hash duplicate
        if self.is_hash_processed(file_hash):
            return {
                "status": "SKIPPED_DUPLICATE",
                "reason": "SHA-256 Content Duplicate",
                "sha256": file_hash,
                "filename": filename
            }

        # Apply quarantine naming suffix if threat detected
        final_filename = filename
        if verdict in ("QUARANTINE_VIRUS", "SUSPICIOUS_STEALER") or "Quarantine" in destination_subpath:
            if not final_filename.endswith(".quarantined"):
                final_filename = f"{filename}.quarantined"

        norm_subpath = destination_subpath.strip("/\\")

        if self.mode == StorageMode.LOCAL:
            return self._store_local(source_path, norm_subpath, final_filename, file_hash, file_size, url, verdict, metadata)
        else:
            return self._store_gdrive(source_path, norm_subpath, final_filename, file_hash, file_size, url, verdict, metadata)

    def _store_local(
        self,
        source_path: Path,
        subpath: str,
        filename: str,
        file_hash: str,
        file_size: int,
        url: str,
        verdict: str,
        metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        dest_dir = self.local_root / subpath
        dest_dir.mkdir(parents=True, exist_ok=True)

        target_file = dest_dir / filename
        # Avoid filename collision if different file
        if target_file.exists():
            base_stem = target_file.stem
            suffix = target_file.suffix
            counter = 1
            while target_file.exists():
                target_file = dest_dir / f"{base_stem}_{counter}{suffix}"
                counter += 1

        shutil.copy2(source_path, target_file)

        # Update Ledger
        self.ledger.setdefault("processed_urls", []).append(url)
        self.ledger.setdefault("processed_hashes", []).append(file_hash)
        record = {
            "filename": target_file.name,
            "original_filename": filename,
            "destination_path": str(target_file.relative_to(self.local_root)),
            "absolute_path": str(target_file),
            "sha256": file_hash,
            "size_bytes": file_size,
            "url": url,
            "backend": "local",
            "verdict": verdict,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {}
        }
        self.ledger.setdefault("records", []).append(record)
        self._save_ledger()

        return {
            "status": "SUCCESS",
            "backend": "local",
            "path": str(target_file),
            "relative_path": str(target_file.relative_to(self.local_root)),
            "filename": target_file.name,
            "sha256": file_hash,
            "size_bytes": file_size,
            "verdict": verdict
        }

    def _store_gdrive(
        self,
        source_path: Path,
        subpath: str,
        filename: str,
        file_hash: str,
        file_size: int,
        url: str,
        verdict: str,
        metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        parent_id = self._resolve_or_create_gdrive_folder(subpath)

        # Prepare gdrive CLI environment
        env = os.environ.copy()
        if self.gdrive_account:
            env["AGY_ACCOUNT"] = self.gdrive_account

        cmd = ["gdrive", "mutate", "upload", str(source_path), "--parent", parent_id]
        res = subprocess.run(cmd, capture_output=True, text=True, env=env, shell=True)

        if res.returncode != 0:
            raise RuntimeError(f"Google Drive upload failed: {res.stderr.strip() or res.stdout.strip()}")

        drive_file_id = None
        for line in res.stdout.splitlines():
            if "(ID:" in line:
                drive_file_id = line.split("(ID:")[1].split(")")[0].strip()
                break

        # Update Ledger
        self.ledger.setdefault("processed_urls", []).append(url)
        self.ledger.setdefault("processed_hashes", []).append(file_hash)
        record = {
            "filename": filename,
            "drive_file_id": drive_file_id,
            "parent_folder_id": parent_id,
            "destination_folder": subpath,
            "sha256": file_hash,
            "size_bytes": file_size,
            "url": url,
            "backend": "gdrive",
            "verdict": verdict,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {}
        }
        self.ledger.setdefault("records", []).append(record)
        self._save_ledger()

        return {
            "status": "SUCCESS",
            "backend": "gdrive",
            "drive_file_id": drive_file_id,
            "parent_id": parent_id,
            "destination_folder": subpath,
            "filename": filename,
            "sha256": file_hash,
            "size_bytes": file_size,
            "verdict": verdict
        }

    def _resolve_or_create_gdrive_folder(self, subpath: str) -> str:
        parts = [p for p in subpath.replace("\\", "/").split("/") if p]
        if not parts:
            return self.gdrive_root_id or "root"

        current_path = ""
        parent_id = self.gdrive_root_id or None

        env = os.environ.copy()
        if self.gdrive_account:
            env["AGY_ACCOUNT"] = self.gdrive_account

        for part in parts:
            current_path = f"{current_path}/{part}" if current_path else part
            if current_path in self.folder_cache:
                parent_id = self.folder_cache[current_path]
                continue

            cmd = ["gdrive", "mutate", "mkdir", part]
            if parent_id:
                cmd.extend(["--parent", parent_id])

            res = subprocess.run(cmd, capture_output=True, text=True, env=env, shell=True)
            if res.returncode != 0:
                raise RuntimeError(f"Failed to create Google Drive folder '{part}': {res.stderr}")

            new_id = None
            for line in res.stdout.splitlines():
                if "(ID:" in line:
                    new_id = line.split("(ID:")[1].split(")")[0].strip()
                    break

            if not new_id:
                raise RuntimeError(f"Could not parse ID from gdrive mkdir output: {res.stdout}")

            self.folder_cache[current_path] = new_id
            parent_id = new_id

        return parent_id

    def get_stats(self) -> Dict[str, Any]:
        records = self.ledger.get("records", [])
        clean_count = sum(1 for r in records if r.get("verdict") == "CLEAN")
        quarantine_count = sum(1 for r in records if r.get("verdict") in ("QUARANTINE_VIRUS", "SUSPICIOUS_STEALER"))
        total_bytes = sum(r.get("size_bytes", 0) for r in records)

        return {
            "total_stored": len(records),
            "clean_files": clean_count,
            "quarantined_files": quarantine_count,
            "unique_hashes": len(self.ledger.get("processed_hashes", [])),
            "total_bytes": total_bytes,
            "backend": self.mode,
            "storage_path": str(self.local_root) if self.mode == StorageMode.LOCAL else "Google Drive"
        }
