import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from strawberryremote import mpris, server


def start(token="secret"):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(token))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def req(url, data=None, cookie=None, ctype="application/json"):
    r = urllib.request.Request(url, data=data, headers={"Content-Type": ctype})
    if cookie:
        r.add_header("Cookie", cookie)
    try:
        return urllib.request.build_opener(NoRedirect).open(r)
    except urllib.error.HTTPError as e:
        return e


def test_requires_token():
    srv, base = start()
    assert req(base + "/api/state").code == 401
    assert req(base + "/?t=wrong").code == 403
    r = req(base + "/?t=secret")
    assert r.code == 303 and "sr_token=secret" in r.headers["Set-Cookie"]
    assert "SameSite=Strict" in r.headers["Set-Cookie"]
    srv.shutdown()


def test_post_needs_auth_and_json():
    srv, base = start()
    assert req(base + "/api/cmd", b"{}").code == 401
    assert req(base + "/api/cmd", b"{}", "sr_token=secret", "text/plain").code == 400
    assert req(base + "/api/cmd", b'{"action":"rm -rf"}', "sr_token=secret").code == 400
    assert req(base + "/api/cmd", b'{"action":"volume","value":5}', "sr_token=secret").code == 400
    srv.shutdown()


def test_cover_path_is_restricted(tmp_path):
    assert server.cover_path("file:///etc/passwd") is None
    assert server.cover_path("http://x/y.jpg") is None
    assert server.cover_path("file:///tmp/strawberry-cover-../../etc/passwd") is None


def test_command_whitelist():
    for bad in ({"action": "x"}, {"action": "loop", "value": "Weird"}):
        try:
            mpris.command(bad)
        except ValueError:
            continue
        raise AssertionError(bad)
