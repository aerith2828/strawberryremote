"""Thin MPRIS2 client on top of busctl (no python dbus bindings needed)."""
import json
import subprocess

BUS = "org.mpris.MediaPlayer2.strawberry"
PATH = "/org/mpris/MediaPlayer2"
PLAYER = "org.mpris.MediaPlayer2.Player"
LOOPS = ("None", "Track", "Playlist")
SIMPLE = {"play": "Play", "pause": "Pause", "playpause": "PlayPause",
          "next": "Next", "prev": "Previous", "stop": "Stop"}


class PlayerGone(Exception):
    pass


def _busctl(*args):
    try:
        r = subprocess.run(["busctl", "--user", "--json=short", *args],
                           capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise PlayerGone(str(e))
    if r.returncode != 0:
        raise PlayerGone(r.stderr.strip() or "busctl failed")
    return r.stdout


def _unwrap(v):
    return v["data"] if isinstance(v, dict) and "data" in v else v


def state():
    out = _busctl("call", BUS, PATH, "org.freedesktop.DBus.Properties", "GetAll", "s", PLAYER)
    props = {k: _unwrap(v) for k, v in json.loads(out)["data"][0].items()}
    meta = {k: _unwrap(v) for k, v in props.get("Metadata", {}).items()}
    first = lambda x: ", ".join(x) if isinstance(x, list) else (x or "")
    return {
        "status": props.get("PlaybackStatus", "Stopped"),
        "title": meta.get("xesam:title", ""),
        "artist": first(meta.get("xesam:artist")),
        "album": meta.get("xesam:album", ""),
        "length": meta.get("mpris:length", 0),
        "position": props.get("Position", 0),
        "volume": props.get("Volume", 0.0),
        "shuffle": props.get("Shuffle", False),
        "loop": props.get("LoopStatus", "None"),
        "trackid": meta.get("mpris:trackid", ""),
        "art_url": meta.get("mpris:artUrl", ""),
        "can_seek": props.get("CanSeek", False),
    }


def _call(method, sig="", *vals):
    _busctl("call", BUS, PATH, PLAYER, method, *([sig, *vals] if sig else []))


def _set(prop, sig, val):
    _busctl("set-property", BUS, PATH, PLAYER, prop, sig, val)


def command(body):
    """Execute one whitelisted command; raises ValueError on bad input."""
    action = body.get("action")
    if action in SIMPLE:
        _call(SIMPLE[action])
    elif action == "volume":
        v = float(body["value"])
        if not 0.0 <= v <= 1.0:
            raise ValueError("volume out of range")
        _set("Volume", "d", repr(v))
    elif action == "seek":
        pos = int(body["value"])
        st = state()
        if pos < 0 or pos > st["length"] or not st["trackid"]:
            raise ValueError("position out of range")
        _call("SetPosition", "ox", st["trackid"], str(pos))
    elif action == "shuffle":
        _set("Shuffle", "b", "true" if body["value"] else "false")
    elif action == "loop":
        if body["value"] not in LOOPS:
            raise ValueError("bad loop mode")
        _set("LoopStatus", "s", body["value"])
    else:
        raise ValueError("unknown action")
