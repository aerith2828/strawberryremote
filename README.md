# strawberryremote

Control the [Strawberry](https://www.strawberrymusicplayer.org/) music player
running on your computer from a phone browser on the same network.

A small web app (Python 3.9+, standard library only) that talks to Strawberry
over MPRIS2 on the session D-Bus, using `busctl` (part of systemd). No
browser extension, no app on the phone.

## Run

```
python3 -m strawberryremote          # from a clone
# or: pip install . (venv / pipx), then: strawberryremote
```

It prints a link like `http://192.168.0.5:8765/?t=TOKEN` (and a QR code if
`qrencode` is installed). Open it on the phone once; the token is stored in a
cookie. Features: play/pause, previous/next, seek, volume, shuffle, repeat
mode, cover art, track info.

| option | meaning |
|---|---|
| `--host 127.0.0.1` | local only (default `0.0.0.0`, all interfaces) |
| `--port N` | default 8765 |
| `--follow` | service mode: open the port only while Strawberry is running |
| `--new-token` | invalidate the old link and generate a new token |

The token lives in `~/.config/strawberryremote/token` (mode 600).

## Start and stop with Strawberry (systemd)

```
mkdir -p ~/.config/systemd/user
cp contrib/strawberryremote.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now strawberryremote
```

The unit runs `--follow`: a light watcher that opens the HTTP port when
Strawberry appears on the session bus and closes it when Strawberry exits
(checked every 3 s). Adjust `PYTHONPATH` in the unit if the clone lives
elsewhere. The link is the one in `journalctl --user -u strawberryremote`.

## Security

- Plain HTTP on the local network: anyone who can see your traffic can read
  the token and control playback. Do not expose the port to the internet.
- Every request needs the token cookie (`HttpOnly`, `SameSite=Strict`); the
  command endpoint accepts only `application/json` and a fixed whitelist of
  actions with validated values.
- Cover art is served only from Strawberry's own temp/cache locations.
- If the phone cannot connect, your firewall probably blocks the port: allow
  TCP 8765 from your LAN only.

## Limits

MPRIS has no playlist or library browsing, so this is a remote control, not a
full client. Next steps could be queue display or search via Strawberry's
database.

## Tests

```
PYTHONPATH=. python3 -m pytest tests
```

MIT licensed.
