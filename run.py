"""Start the local dashboard.

    python run.py                 # http://127.0.0.1:8713, opens a browser
    python run.py --port 9000
    python run.py --no-browser
"""

import argparse
import os

from cfc.server import serve

# Managed hosts (Render, Railway, Fly, Heroku) inject PORT and require the
# process to bind 0.0.0.0. Locally we stay on loopback, which is the posture
# the tool is designed for.
ENV_PORT = os.environ.get("PORT")
DEFAULT_PORT = int(ENV_PORT) if ENV_PORT else 8713
DEFAULT_HOST = os.environ.get("HOST") or ("0.0.0.0" if ENV_PORT else "127.0.0.1")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Cyber Fraud Correlator dashboard")
    ap.add_argument("--host", default=DEFAULT_HOST,
                    help="bind address (default loopback; 0.0.0.0 when PORT is set)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--no-demo", action="store_true",
                    help="start empty instead of pre-loading the demonstration case")
    args = ap.parse_args()
    # never try to open a browser on a headless host
    serve(args.host, args.port,
          open_browser=not args.no_browser and not ENV_PORT,
          demo=not args.no_demo)
