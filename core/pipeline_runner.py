"""
Pipeline Runner: Threaded Orchestrator for Discord Ingestion, Threat Scanning,
and Storage Management with UI Event Dispatching.
"""

import os
import time
import json
import threading
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable

from core.discord_client import DiscordClient
from core.security_scanner import SecurityScanner
from core.triage_engine import TriageEngine
from core.storage_manager import StorageManager

ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.dll', '.sys', '.exe', '.cpp', '.h', '.hpp'}


class PipelineRunner:
    """
    Coordinates asynchronous Discord ingestion, threat evaluation, and storage.
    """

    def __init__(
        self,
        config: Dict[str, Any],
        on_log: Optional[Callable[[str, str], None]] = None,
        on_metrics: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_finish: Optional[Callable[[], None]] = None
    ):
        self.config = config
        self.on_log = on_log or (lambda lvl, msg: print(f"[{lvl}] {msg}"))
        self.on_metrics = on_metrics or (lambda m: None)
        self.on_finish = on_finish or (lambda: None)

        self.discord_cfg = config.get("discord", {})
        self.token = self.discord_cfg.get("token", "").strip()
        self.servers = self.discord_cfg.get("servers", [])
        self.history_depth = int(self.discord_cfg.get("history_depth", 500))
        self.skip_keywords = [k.lower() for k in self.discord_cfg.get("skip_channel_keywords", [])]

        self.client = DiscordClient(self.token)
        self.triage = TriageEngine()
        self.storage = StorageManager(config)

        self.webhook_cfg = config.get("webhook", {})
        self.webhook_enabled = self.webhook_cfg.get("enabled", False)
        self.webhook_url = self.webhook_cfg.get("url", "http://localhost:5678/webhook/discord/source-eval")

        self.is_running = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Metrics
        self.metrics = {
            "channels_scanned": 0,
            "messages_analyzed": 0,
            "candidates_found": 0,
            "clean_saved": 0,
            "quarantined": 0,
            "duplicates_skipped": 0
        }

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        if not self.is_running:
            return
        self.on_log("INFO", "Stopping pipeline runner... (waiting for current file to complete)")
        self._stop_event.set()
        self.is_running = False

    def _emit_metrics(self):
        combined = {**self.metrics, **self.storage.get_stats()}
        self.on_metrics(combined)

    def _forward_webhook(self, payload: Dict[str, Any]):
        if not self.webhook_enabled or not self.webhook_url:
            return
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(self.webhook_url, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                pass
        except Exception:
            pass

    def _run_loop(self):
        self.on_log("INFO", f"Starting Ingestion Pipeline with {len(self.servers)} server(s)...")
        self.on_log("INFO", f"Storage Backend: {self.storage.mode.upper()} -> {self.storage.local_root if self.storage.mode == 'local' else 'Google Drive'}")

        # Validate token
        valid, auth_name = self.client.test_connection()
        if not valid:
            self.on_log("ERROR", f"Discord authentication failed: {auth_name}")
            self.is_running = False
            self.on_finish()
            return

        self.on_log("INFO", f"Authenticated with Discord as: {auth_name}")

        temp_dir = Path(tempfile.gettempdir())

        for srv in self.servers:
            if self._stop_event.is_set():
                break

            s_id = str(srv.get("server_id", "")).strip()
            s_name = srv.get("name", f"Server-{s_id}")
            explicit_channels = srv.get("channel_ids", [])

            self.on_log("INFO", f"Enumerating channels for {s_name} ({s_id})...")
            target_channels = []

            if explicit_channels:
                for cid in explicit_channels:
                    target_channels.append({"id": str(cid), "name": f"channel-{cid}"})
            else:
                guild_channels = self.client.get_guild_channels(s_id)
                for gc in guild_channels:
                    cname = gc.get("name", "").lower()
                    if not any(sk in cname for sk in self.skip_keywords):
                        target_channels.append({"id": str(gc.get("id")), "name": gc.get("name", "unnamed")})

            self.on_log("INFO", f"Found {len(target_channels)} candidate channel(s) in {s_name}")

            for ch in target_channels:
                if self._stop_event.is_set():
                    break

                cid = ch["id"]
                cname = ch["name"]
                self.on_log("SCAN", f"Scanning #{cname} on [{s_name}]...")
                self.metrics["channels_scanned"] += 1
                self._emit_metrics()

                fetched_total = 0
                last_id = None

                while fetched_total < self.history_depth and not self._stop_event.is_set():
                    batch_limit = min(100, self.history_depth - fetched_total)
                    code, messages = self.client.fetch_messages(cid, limit=batch_limit, before_id=last_id)

                    if code == 403:
                        self.on_log("WARN", f"#{cname} is private (403 Forbidden). Skipping.")
                        break
                    if not messages or not isinstance(messages, list):
                        break

                    fetched_total += len(messages)
                    self.metrics["messages_analyzed"] += len(messages)
                    self._emit_metrics()

                    for msg in messages:
                        if self._stop_event.is_set():
                            break

                        attachments = msg.get("attachments", [])
                        if not attachments:
                            continue

                        for att in attachments:
                            fname = att.get("filename", "")
                            url = att.get("url", "")
                            ext = ("." + fname.split(".")[-1].lower()) if "." in fname else ""

                            if ext not in ARCHIVE_EXTENSIONS or not url:
                                continue

                            self.metrics["candidates_found"] += 1

                            # 1. Fast URL Deduplication
                            if self.storage.is_url_processed(url):
                                self.metrics["duplicates_skipped"] += 1
                                self._emit_metrics()
                                continue

                            self.on_log("PROCESS", f"Downloading: {fname} from #{cname}...")
                            tmp_path = temp_dir / f"sentinel_tmp_{fname}"

                            try:
                                if not self.client.download_file(url, tmp_path):
                                    self.on_log("WARN", f"Failed to download {fname}")
                                    continue

                                # 2. Deep In-Archive Threat Inspection
                                verdict, threats, namelist = SecurityScanner.scan_archive(tmp_path)

                                # 3. Taxonomy Classification
                                msg_payload = {
                                    "content": (msg.get("content", "") + " " + fname + " " + " ".join(namelist)).strip(),
                                    "timestamp": msg.get("timestamp"),
                                    "server_name": s_name,
                                    "channel_name": cname,
                                    "author_name": msg.get("author", {}).get("username", "Unknown"),
                                    "message_id": msg.get("id")
                                }
                                triage_meta = self.triage.evaluate(msg_payload)
                                dest_folder = triage_meta.get("decision", {}).get("destination_folder", "Other/Utilities/")

                                if verdict in ("QUARANTINE_VIRUS", "SUSPICIOUS_STEALER"):
                                    dest_folder = f"Quarantine/{'Detected_Viruses' if verdict == 'QUARANTINE_VIRUS' else 'Suspicious_Stealers'}/"
                                    self.on_log("THREAT", f"QUARANTINE: {fname} -> Threats: {'; '.join(threats[:2])}")
                                    self.metrics["quarantined"] += 1
                                else:
                                    self.on_log("CLEAN", f"CLEAN: {fname} -> Target: {dest_folder}")
                                    self.metrics["clean_saved"] += 1

                                # 4. Storage Persistence (Local Disk OR Google Drive)
                                store_result = self.storage.store_file(
                                    source_path=tmp_path,
                                    destination_subpath=dest_folder,
                                    filename=fname,
                                    url=url,
                                    verdict=verdict,
                                    metadata=triage_meta
                                )

                                if store_result.get("status") == "SKIPPED_DUPLICATE":
                                    self.on_log("INFO", f"Deduplicated by SHA-256: {fname}")
                                    self.metrics["duplicates_skipped"] += 1
                                elif store_result.get("status") == "SUCCESS":
                                    self.on_log("SAVED", f"Successfully stored [{store_result.get('backend').upper()}]: {store_result.get('filename')}")

                                self._forward_webhook(triage_meta)
                                self._emit_metrics()

                            except Exception as e:
                                self.on_log("ERROR", f"Processing error on {fname}: {e}")
                            finally:
                                if tmp_path.exists():
                                    tmp_path.unlink(missing_ok=True)

                            time.sleep(0.2)

                    last_id = messages[-1].get("id")
                    if len(messages) < batch_limit:
                        break
                    time.sleep(0.3)

        self.on_log("INFO", "Ingestion run finished.")
        self.is_running = False
        self._emit_metrics()
        self.on_finish()
