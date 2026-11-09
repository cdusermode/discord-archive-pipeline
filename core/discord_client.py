"""
Discord API Client: Guild Channel Enumeration, Message Pagination,
Rate-Limit Backoff (HTTP 429), and Attachment Streaming.
"""

import sys
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional


class DiscordClient:
    """
    Robust Discord REST API wrapper for guild and channel message ingestion.
    """

    API_BASE = "https://discord.com/api/v10"

    def __init__(self, token: str):
        self.token = token.strip()

    def get_headers(self) -> Dict[str, str]:
        auth = self.token
        return {
            "Authorization": auth,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

    def test_connection(self) -> Tuple[bool, str]:
        """
        Validates token against Discord API /users/@me.
        Returns: (success, username_or_error)
        """
        if not self.token or self.token == "YOUR_DISCORD_TOKEN_HERE":
            return False, "Discord Token not configured."

        url = f"{self.API_BASE}/users/@me"
        req = urllib.request.Request(url, headers=self.get_headers())
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                username = data.get("username", "Unknown")
                tag = data.get("discriminator", "0")
                return True, f"{username}#{tag}" if tag != "0" else username
        except urllib.error.HTTPError as e:
            return False, f"HTTP {e.code}: Unauthorized or Invalid Token."
        except Exception as e:
            return False, f"Connection Error: {e}"

    def get_guild_info(self, guild_id: str) -> Tuple[bool, Dict[str, Any]]:
        url = f"{self.API_BASE}/guilds/{guild_id.strip()}"
        req = urllib.request.Request(url, headers=self.get_headers())
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return True, data
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(3)
                return self.get_guild_info(guild_id)
            return False, {"error": f"HTTP {e.code}"}
        except Exception as e:
            return False, {"error": str(e)}

    def get_guild_channels(self, guild_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves all accessible text and announcement channels (type 0 and 5).
        """
        url = f"{self.API_BASE}/guilds/{guild_id.strip()}/channels"
        req = urllib.request.Request(url, headers=self.get_headers())
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                channels = json.loads(resp.read().decode("utf-8"))
                return [c for c in channels if c.get("type") in (0, 5)]
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(3)
                return self.get_guild_channels(guild_id)
            return []
        except Exception:
            return []

    def fetch_messages(
        self,
        channel_id: str,
        limit: int = 100,
        before_id: Optional[str] = None
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Fetches up to `limit` messages from a channel with rate limit (429) backoff.
        """
        url = f"{self.API_BASE}/channels/{channel_id}/messages?limit={min(100, limit)}"
        if before_id:
            url += f"&before={before_id}"

        req = urllib.request.Request(url, headers=self.get_headers())
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return 200, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                retry_after = 5
                try:
                    body = json.loads(e.read().decode("utf-8"))
                    retry_after = float(body.get("retry_after", 5.0))
                except Exception:
                    pass
                time.sleep(retry_after + 0.5)
                return self.fetch_messages(channel_id, limit=limit, before_id=before_id)
            return e.code, []
        except Exception:
            return 500, []

    def download_file(self, url: str, target_path: Path, timeout: int = 30) -> bool:
        """
        Streams binary data directly to disk.
        """
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp, open(target_path, "wb") as f:
                while chunk := resp.read(65536):
                    f.write(chunk)
            return True
        except Exception as e:
            if target_path.exists():
                target_path.unlink(missing_ok=True)
            return False
