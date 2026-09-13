"""Start the local dashboard.

    python run.py                 # http://127.0.0.1:8713, opens a browser
    python run.py --port 9000
    python run.py --no-browser
"""

import argparse

from cfc.server import serve

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Cyber Fraud Correlator dashboard")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default loopback only)")
    ap.add_argument("--port", type=int, default=8713)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--no-demo", action="store_true",
                    help="start empty instead of pre-loading the demonstration case")
    args = ap.parse_args()
    serve(args.host, args.port, open_browser=not args.no_browser,
          demo=not args.no_demo)
