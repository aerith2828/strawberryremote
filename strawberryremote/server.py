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
from collections import defaultdict
import urllib.parse
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import mpris

CONF_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "strawberryremote"
COVER_DIRS = ("/tmp/strawberry-cover-", str(Path.home() / ".local/share/strawberry/strawberry/"))
INDEX = (Path(__file__).parent / "index.html").read_bytes()
LOGIN = (Path(__file__).parent / "login.html").read_bytes()
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


def load_pin():
    f = CONF_DIR / "pin"
    return f.read_text().strip() if f.exists() else None


def save_pin(pin):
    if not (pin.isdigit() and 4 <= len(pin) <= 8):
        raise SystemExit("PIN must be 4-8 digits")
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(CONF_DIR / "pin", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(pin + "\n")


class Throttle:
    """Lock an IP out for LOCK seconds after MAX wrong PINs."""
    MAX, LOCK = 5, 300

    def __init__(self, now=time.monotonic):
        self.now, self.fails, self.until, self.mu = now, defaultdict(int), {}, threading.Lock()

    def blocked(self, ip):
        with self.mu:
            return self.until.get(ip, 0) > self.now()

    def failed(self, ip):
        with self.mu:
            self.fails[ip] += 1
            if self.fails[ip] >= self.MAX:
                self.until[ip] = self.now() + self.LOCK
                self.fails[ip] = 0

    def ok(self, ip):
        with self.mu:
            self.fails.pop(ip, None)


def cover_path(art_url):
    if not art_url.startswith("file://"):
        return None
    p = os.path.realpath(urllib.parse.unquote(art_url[7:]))
    return p if p.startswith(COVER_DIRS) and os.path.isfile(p) else None


def make_handler(token, pin=None, throttle=None):
    throttle = throttle or Throttle()

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
                if u.path == "/" and pin:
                    return self._send(200, LOGIN, "text/html; charset=utf-8",
                                      [("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")])
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

        def _login(self):
            ip = self.client_address[0]
            if not pin:
                return self._send(404, b"", "text/plain")
            if throttle.blocked(ip):
                return self._json(429, {"error": "too many attempts"})
            try:
                n = int(self.headers.get("Content-Length", 0))
                if n > 256:
                    raise ValueError("too large")
                got = str(json.loads(self.rfile.read(n)).get("pin", ""))
            except (ValueError, AttributeError):
                return self._json(400, {"error": "bad request"})
            if not hmac.compare_digest(got.encode(), pin.encode()):
                throttle.failed(ip)
                return self._json(403, {"error": "wrong pin"})
            throttle.ok(ip)
            cookie = "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000" % (COOKIE, token)
            self._send(200, b'{"ok": true}', extra=[("Set-Cookie", cookie)])

        def do_POST(self):
            if self.path == "/login" and self.headers.get("Content-Type", "").split(";")[0] == "application/json":
                return self._login()
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
    p.add_argument("--set-pin", metavar="DIGITS", help="store a 4-8 digit PIN for logging in from the phone, then exit")
    p.add_argument("--new-token", action="store_true", help="invalidate the old link and generate a new token")
    args = p.parse_args(argv)

    if args.set_pin:
        save_pin(args.set_pin)
        print("PIN saved to %s" % (CONF_DIR / "pin"))
        return 0
    token = load_token(args.new_token)
    pin = load_pin()
    host = lan_ip() if args.host in ("0.0.0.0", "") else args.host
    url = "http://%s:%d/?t=%s" % (host, args.port, token)
    if pin:
        print("Open on your phone (same network) and enter the PIN:\n  http://%s.local:%d\n  http://%s:%d" % (
            socket.gethostname(), args.port, host, args.port), flush=True)
        print("or, without PIN:\n  " + url, flush=True)
    else:
        print("Open on your phone (same network):\n  " + url, flush=True)
    try:
        qr = subprocess.run(["qrencode", "-t", "ANSIUTF8", url], capture_output=True, text=True)
        if qr.returncode == 0:
            print(qr.stdout)
    except OSError:
        pass
    print("Plain HTTP: anyone on the network who sees the link can control playback. Ctrl+C to stop.", flush=True)
    handler = make_handler(token, pin)

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
