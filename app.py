"""
Sentinel Vault - Discord Archive Ingestion, Static Security Triage & Dual Storage Engine.
Entrypoint: Run with GUI (default) or headless CLI mode.
"""

import sys
import argparse
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ui.imgui_dashboard import ImGuiDashboard, load_app_config
from core.pipeline_runner import PipelineRunner


def run_cli():
    print("==================================================================")
    print("  Sentinel Vault // Headless CLI Ingestion Engine")
    print("==================================================================")
    config = load_app_config()

    def cli_log(level: str, msg: str):
        print(f"[{level:<7}] {msg}")

    def cli_metrics(m):
        pass

    def cli_finish():
        print("\n[+] CLI Run finished.")

    runner = PipelineRunner(
        config=config,
        on_log=cli_log,
        on_metrics=cli_metrics,
        on_finish=cli_finish
    )
    runner.start()
    try:
        while runner.is_running:
            runner._thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Stopping runner...")
        runner.stop()
        runner._thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description="Sentinel Vault Discord Ingestion Engine")
    parser.add_argument("--cli", action="store_true", help="Run headlessly in CLI mode without opening the ImGui GUI")
    args = parser.parse_args()

    if args.cli:
        run_cli()
    else:
        app = ImGuiDashboard()
        app.run()


if __name__ == "__main__":
    main()
