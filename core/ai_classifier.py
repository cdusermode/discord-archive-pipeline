"""
AI Classifier Module: Neural & LLM-Powered Codebase Classification.
Supports:
- Google Gemini API (Free tier: gemini-1.5-flash / gemini-2.0-flash)
- OpenAI API (gpt-4o-mini)
- Local Ollama (offline, zero-cost: llama3, mistral, deepseek-r1)
- Seamless fallback to Deep Code Heuristic Analyzer
"""

import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List, Tuple


SYSTEM_PROMPT = """You are an expert low-level systems engineering and reverse-engineering classifier.
Analyze the codebase files, signatures, and code snippets, then classify into this exact JSON schema:
{
  "target_game": "Fortnite" | "CounterStrike_CS2" | "CounterStrike_CSGO" | "Rust" | "Roblox" | "Grand_Theft_Auto_V" | "Rainbow_Six_Siege" | "Minecraft_Java" | "Other",
  "category": "Tools" | "Cheat" | "Spoofer" | "Utility",
  "destination_folder": string,
  "confidence": float,
  "reasoning": string
}

Taxonomy Rules:
- If it is a Driver (.sys, DriverEntry, IoCreateDevice) for EAC/BE/Vanguard/General:
  destination_folder must be "Tools/Drivers/"
- If it is a Mapper (kdmapper, VDM, drvmap, vulnerable driver loader):
  destination_folder must be "Tools/Mappers/"
- If it is an Injector (CreateRemoteThread, ManualMap, LoadLibrary):
  if game is detected: "Games/<Game>/Internal/Injectors/", else "Tools/Injectors/"
- If it is a Spoofer (HWID, serials, MAC, SMBIOS):
  "Spoofer/Universal/Temp/" or "Spoofer/Universal/Perm/"
- If it is a Game Cheat:
  - Kernel driver based: "Games/<Game>/External/Kernel/"
  - Usermode overlay/external: "Games/<Game>/External/UserMode/"
  - Internal DLL: "Games/<Game>/Internal/DLL/"
- Output ONLY raw valid JSON. No markdown ticks, no commentary.
"""


class AIClassifier:
    """
    LLM-powered codebase classification engine.
    """

    def __init__(self, config: Dict[str, Any]):
        self.ai_cfg = config.get("ai_classification", {})
        self.enabled = self.ai_cfg.get("enabled", False)
        self.provider = self.ai_cfg.get("provider", "gemini").lower()
        self.api_key = self.ai_cfg.get("api_key", "").strip()
        self.model = self.ai_cfg.get("model", "gemini-1.5-flash").strip()
        self.ollama_endpoint = self.ai_cfg.get("ollama_endpoint", "http://localhost:11434").strip()

    def classify_codebase(
        self,
        filename: str,
        file_tree: List[str],
        code_snippets: str,
        message_context: str
    ) -> Optional[Dict[str, Any]]:
        """
        Sends codebase summary to selected LLM. Returns structured decision dict or None on failure.
        """
        if not self.enabled:
            return None

        prompt_payload = {
            "archive_filename": filename,
            "internal_files": file_tree[:60],
            "message_text": message_context[:500],
            "code_extracts": code_snippets[:2000]
        }

        user_content = json.dumps(prompt_payload, indent=2)

        try:
            if self.provider == "gemini":
                return self._call_gemini(user_content)
            elif self.provider == "openai":
                return self._call_openai(user_content)
            elif self.provider == "ollama":
                return self._call_ollama(user_content)
        except Exception as e:
            print(f"[AI Classifier] LLM query failed ({self.provider}): {e}")
            return None

        return None

    def _call_gemini(self, user_content: str) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            return None

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        body = {
            "contents": [
                {
                    "parts": [
                        {"text": SYSTEM_PROMPT + "\n\nAnalyze this candidate:\n" + user_content}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json"
            }
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            res_data = json.loads(resp.read().decode("utf-8"))
            candidates = res_data.get("candidates", [])
            if candidates:
                text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                return json.loads(text.strip("` \n").replace("json\n", ""))
        return None

    def _call_openai(self, user_content: str) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            return None

        url = "https://api.openai.com/v1/chat/completions"
        body = {
            "model": self.model if self.model else "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content}
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        })
        with urllib.request.urlopen(req, timeout=12) as resp:
            res_data = json.loads(resp.read().decode("utf-8"))
            choice = res_data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return json.loads(choice.strip())
        return None

    def _call_ollama(self, user_content: str) -> Optional[Dict[str, Any]]:
        endpoint = f"{self.ollama_endpoint.rstrip('/')}/api/generate"
        body = {
            "model": self.model if self.model else "llama3",
            "prompt": SYSTEM_PROMPT + "\n\nAnalyze this candidate:\n" + user_content,
            "stream": False,
            "format": "json"
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            res_data = json.loads(resp.read().decode("utf-8"))
            resp_text = res_data.get("response", "")
            return json.loads(resp_text.strip())
        return None
