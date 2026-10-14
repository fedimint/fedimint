"""Capture the exported Rust renderer fixtures with sandboxed Chromium."""

import argparse
import functools
import http.server
import pathlib
import subprocess
import tempfile
import threading

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("chromium", help="Path to a Chromium executable")
parser.add_argument("fixtures", help="Directory produced by export_browser_fixtures")
parser.add_argument("--output", type=pathlib.Path, help="Screenshot destination directory")
args = parser.parse_args()
destination = args.output or pathlib.Path(__file__).resolve().parent
destination.mkdir(parents=True, exist_ok=True)
handler = functools.partial(
    http.server.SimpleHTTPRequestHandler, directory=args.fixtures
)
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
thread = threading.Thread(target=server.serve_forever)
thread.start()
try:
    for page, size, name in [
        ("observed", "1440,1000", "observed-desktop"),
        ("observed", "390,1350", "observed-mobile"),
        ("startup", "1440,1000", "startup"),
        ("stale", "1440,1000", "stale"),
    ]:
        with tempfile.TemporaryDirectory(
            prefix="guardian-browser.", dir=args.fixtures
        ) as profile:
            subprocess.run(
                [
                    args.chromium,
                    "--headless",
                    f"--user-data-dir={profile}",
                    f"--window-size={size}",
                    "--timeout=10000",
                    f"--screenshot={destination / (name + '.png')}",
                    f"http://127.0.0.1:{server.server_port}/{page}.html",
                ],
                check=True,
                timeout=45,
            )
finally:
    server.shutdown()
    thread.join()
    server.server_close()
