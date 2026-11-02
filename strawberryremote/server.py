import argparse
import hmac
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import mpris

CONF_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "strawberryremote"
COVER_DIRS = ("/tmp/strawberry-cover-", str(Path.home() / ".local/share/strawberry/strawberry/"))
INDEX = (Path(__file__).parent / "index.html").read_bytes()
COOKIE = "sr_token"


def load_token(regenerate=False):
    f = CONF_DIR / "token"
    if f.exists() and not regenerate:
        return f.read_text().strip()
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(24)
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token + "\n")
    return token


def cover_path(art_url):
    if not art_url.startswith("file://"):
        return None
    p = os.path.realpath(urllib.parse.unquote(art_url[7:]))
    return p if p.startswith(COVER_DIRS) and os.path.isfile(p) else None


def make_handler(token):
    class H(BaseHTTPRequestHandler):
        server_version = "strawberryremote"

        def log_message(self, fmt, *a):
            sys.stderr.write("%s %s\n" % (self.client_address[0], fmt % a))

        def _send(self, code, body=b"", ctype="application/json", extra=()):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in extra:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj).encode())

        def _authed(self):
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            got = c[COOKIE].value if COOKIE in c else ""
            return hmac.compare_digest(got.encode(), token.encode())

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            q = urllib.parse.parse_qs(u.query)
            if u.path == "/" and "t" in q:
                if hmac.compare_digest(q["t"][0].encode(), token.encode()):
                    cookie = "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000" % (COOKIE, token)
                    return self._send(303, extra=[("Location", "/"), ("Set-Cookie", cookie)])
                return self._send(403, b"bad token", "text/plain")
            if not self._authed():
                return self._send(401, b"open the URL printed by strawberryremote (with ?t=...)", "text/plain")
            if u.path == "/":
                return self._send(200, INDEX, "text/html; charset=utf-8",
                                  [("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:")])
            try:
                if u.path == "/api/state":
                    return self._json(200, mpris.state())
                if u.path == "/api/cover":
                    p = cover_path(mpris.state()["art_url"])
                    if not p:
                        return self._send(404, b"", "text/plain")
                    ctype = "image/png" if p.endswith(".png") else "image/jpeg"
                    return self._send(200, Path(p).read_bytes(), ctype)
            except mpris.PlayerGone as e:
                return self._json(503, {"error": "Strawberry not reachable: %s" % e})
            self._send(404, b"not found", "text/plain")

        def do_POST(self):
            if not self._authed():
                return self._send(401, b"", "text/plain")
            if self.path != "/api/cmd" or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._send(400, b"", "text/plain")
            try:
                n = int(self.headers.get("Content-Length", 0))
                if n > 4096:
                    raise ValueError("too large")
                mpris.command(json.loads(self.rfile.read(n)))
            except mpris.PlayerGone as e:
                return self._json(503, {"error": "Strawberry not reachable: %s" % e})
            except (ValueError, KeyError, TypeError) as e:
                return self._json(400, {"error": str(e)})
            self._json(200, {"ok": True})

    return H


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def player_running(name=mpris.BUS):
    try:
        subprocess.run(["busctl", "--user", "status", name], capture_output=True, check=True, timeout=5)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def follow(is_up, start, stop, stop_event, interval=3.0):
    """Keep the server up exactly while the player is on the bus."""
    srv = None
    while not stop_event.is_set():
        up = is_up()
        if up and srv is None:
            srv = start()
        elif not up and srv is not None:
            stop(srv)
            srv = None
        stop_event.wait(interval)
    if srv is not None:
        stop(srv)


def main(argv=None):
    p = argparse.ArgumentParser(prog="strawberryremote", description="Phone remote for Strawberry (MPRIS).")
    p.add_argument("--host", default="0.0.0.0", help="bind address (default %(default)s; use 127.0.0.1 for local only)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--follow", action="store_true",
                   help="run as a service: serve only while Strawberry is running (for systemd)")
    p.add_argument("--watch-name", default=mpris.BUS, help=argparse.SUPPRESS)
    p.add_argument("--new-token", action="store_true", help="invalidate the old link and generate a new token")
    args = p.parse_args(argv)

    token = load_token(args.new_token)
    host = lan_ip() if args.host in ("0.0.0.0", "") else args.host
    url = "http://%s:%d/?t=%s" % (host, args.port, token)
    print("Open on your phone (same network):\n  " + url, flush=True)
    try:
        qr = subprocess.run(["qrencode", "-t", "ANSIUTF8", url], capture_output=True, text=True)
        if qr.returncode == 0:
            print(qr.stdout)
    except OSError:
        pass
    print("Plain HTTP: anyone on the network who sees the link can control playback. Ctrl+C to stop.", flush=True)
    handler = make_handler(token)

    if args.follow:
        stop_event = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
        signal.signal(signal.SIGINT, lambda *_: stop_event.set())

        def start():
            srv = ThreadingHTTPServer((args.host, args.port), handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            print("strawberry up: serving on port %d" % args.port, flush=True)
            return srv

        def stop(srv):
            srv.shutdown()
            srv.server_close()
            print("strawberry gone: server stopped", flush=True)

        follow(lambda: player_running(args.watch_name), start, stop, stop_event)
        return 0

    ThreadingHTTPServer((args.host, args.port), handler).serve_forever()
