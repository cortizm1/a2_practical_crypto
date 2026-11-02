#!/usr/bin/env python3
"""Local web UI for the JMessage client (extra credit, handout Part 1).

What this file is for
---------------------
A browser front end on top of the supplied driver pieces. It has a directory
page (every registered user with the key the server serves for them and its
§5 fingerprint, to browse and start conversations) and shows, for each
conversation, the truth about its security state: which suite the current
session negotiated (legacy JM1 visibly different from hybrid JM2), the peer's
fingerprint with a hand-set "verified" mark, every warning and error the core
emitted, and a prominent alert that clears the mark when the peer's directory
key changes.

Where it sits
-------------

      browser --htmx--> FastHTML handlers (uvicorn thread)
                              |  enqueue actions / read Inbox snapshot
                              v
                   ProtocolLoop (ONE dedicated thread)
                     runtime.poll()           every --poll-interval s
                     runtime.call(core.xxx)   one queued action at a time
                     core.fingerprint(peer)   periodically, to detect key changes
                              |  Runtime.output(display dict)
                              v
                           Inbox (ui_state.py)

    Handlers never call the Client. They put a closure on a queue that the
    protocol thread drains (README §4 threading note; runtime.py explains why
    the Client must only ever run on one thread). The UI shows message text
    only after the core emitted a `message` event, because that is the only
    place the text exists on this side.

Zone: glue (AGENTS.md). protocol.py is untouched; the UI uses only the
public Client interface: start_handshake, send_text, fingerprint, and the
optional reset_peer_trust.

Run (two terminals, plus `python local_relay.py` in a third):

    python webui.py --server http://127.0.0.1:8765 --username alice --register --port 8010
    python webui.py --server http://127.0.0.1:8765 --username bob   --register --port 8011

then open http://127.0.0.1:8010 and http://127.0.0.1:8011. Needs the optional
UI dependencies: `uv sync --extra ui` (python-fasthtml, monsterui).

Hosted use (optional): put it behind a TLS reverse proxy and set
JMESSAGE_UI_PASSWORD_HASH (from `webui.py --hash-password`; unset = no login
page, local use), JMESSAGE_SECRET_KEY (cookie signing), JMESSAGE_HTTPS=1
(Secure cookie) and, if wanted, JMESSAGE_FOOTER_LINK / JMESSAGE_FOOTER_LABEL
for a small footer link. The hosting configuration is not part of this
submission.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import os
import queue
import secrets
import sys
import threading
import time
import traceback
from pathlib import Path
from urllib.parse import quote

from jmessage_support.codec import encode_text, username
from jmessage_support.identity import load_or_create, public_bytes
from jmessage_support.runtime import Runtime
from jmessage_support.transport import API, PeerKeyUnavailable, TransportError
from ui_state import JM1, JM2, Inbox

FINGERPRINT_REFRESH = 10      # seconds between re-reading an open conversation's directory key
DIRECTORY_REFRESH = 120       # seconds between full directory passes (/users + every key)
PBKDF2_ROUNDS = 600_000


# ----- UI password (hosted deployment only) ----------------------------------------

def hash_password(password):
    """`pbkdf2_sha256$rounds$salt$hash`, for JMESSAGE_UI_PASSWORD_HASH."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def check_password(password, encoded):
    """Constant-time comparison against a `hash_password` string; False for a malformed one."""
    try:
        algorithm, rounds, salt, digest = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt),
                                        int(rounds))
        return hmac.compare_digest(candidate, bytes.fromhex(digest))
    except (ValueError, AttributeError):
        return False


# ----- The single protocol thread -----------------------------------------------

class ProtocolLoop(threading.Thread):
    """Runs every Client call in order on one thread; the web handlers only enqueue."""

    def __init__(self, runtime, inbox, *, poll_interval=2.0, auto_poll=True):
        super().__init__(name="protocol", daemon=True)
        self.runtime = runtime
        self.inbox = inbox
        self.poll_interval = poll_interval
        self.auto_poll = auto_poll
        self.actions = queue.Queue()
        self.stopped = threading.Event()
        self._fp_due = {}      # peer -> monotonic time of the next fingerprint refresh

    # Called from web handlers (any thread).
    def submit(self, label, fn):
        self.actions.put((label, fn))

    def wants_fingerprint(self, peer):
        self._fp_due[peer] = 0.0

    # Protocol-thread work items.
    def _fingerprint(self, peer):
        core = self.runtime.client
        try:
            value = core.fingerprint(peer)
        except PeerKeyUnavailable as exc:
            self.inbox.fingerprint_unavailable(peer, str(exc))
            return
        if peer is None or peer == self.runtime.account:
            self.inbox.apply({"type": "fingerprint", "peer": self.runtime.account, "value": value})
        else:
            self.inbox.set_fingerprint(peer, value)

    def _refresh_fingerprints(self, now):
        for peer in self.inbox.open_peers():
            if now >= self._fp_due.get(peer, 0.0):
                self._fp_due[peer] = now + FINGERPRINT_REFRESH
                self.runtime.call(self._fingerprint, peer, peer=peer)

    def refresh_directory(self):
        """One pass over the directory: the user list, then every user's raw key and fingerprint.

        The raw key is shown as the server sent it (base64, §3); the fingerprint comes from
        `Client.fingerprint`, the one place that knows §5, so a key change is detected for
        every listed user, not only the ones with an open conversation.
        """
        listing = self.runtime.call(self.runtime.api.users)
        self.inbox.apply({"type": "users", "users": listing})
        for name in self.inbox.users:
            if name == self.runtime.account:
                continue
            try:
                raw = self.runtime.api.lookup_key(name)
            except PeerKeyUnavailable as exc:
                self.inbox.set_directory_key(name, None, error=str(exc))
                self.inbox.fingerprint_unavailable(name, str(exc))
                continue
            self.inbox.set_directory_key(name, base64.b64encode(raw).decode("ascii"))
            self.runtime.call(self._fingerprint, name, peer=name)
            self._fp_due[name] = time.monotonic() + FINGERPRINT_REFRESH

    def run(self):
        next_poll = time.monotonic()
        next_directory = 0.0
        try:
            self.runtime.call(self._fingerprint, None)
            while not self.stopped.is_set():
                now = time.monotonic()
                if self.auto_poll and now >= next_poll:
                    next_poll = now + self.poll_interval
                    self._guarded("poll", self.runtime.poll)
                if now >= next_directory:
                    next_directory = now + DIRECTORY_REFRESH
                    self._guarded("directory", self.refresh_directory)
                self._guarded("fingerprints", lambda now=now: self._refresh_fingerprints(now))
                try:
                    label, fn = self.actions.get(timeout=0.1)
                except queue.Empty:
                    continue
                self._guarded(label, fn)
        except TransportError as exc:
            self.inbox.transport_failed(str(exc))
        finally:
            self.stopped.set()

    def _guarded(self, label, fn):
        """Run one work item; a bug in student code is shown, not fatal. Transport failure is."""
        try:
            fn()
        except TransportError:
            raise
        except NotImplementedError as exc:
            self.inbox.note_system(f"Student TODO ({label}): {exc}", kind="error")
        except Exception as exc:     # noqa: BLE001 - a UI must survive and show the traceback
            traceback.print_exc()
            self.inbox.note_system(f"{label} raised {type(exc).__name__}: {exc}", kind="error")


# ----- Start-up (same steps as client.py main, README §4) --------------------------

def connect(args):
    """Register/login, load the identity key, reconcile it with the directory."""
    account = username(args.username)
    api = API(args.server)
    password = (args.password_file.read_text(encoding="utf-8").removesuffix("\n").removesuffix("\r")
                if args.password_file else getpass.getpass("Password: "))
    if not password:
        raise ValueError("password must not be empty")
    if args.register:
        try:
            api.register(account, password)
        except TransportError as exc:
            if exc.status != 409:
                raise
            print("Account already exists; logging in.", file=sys.stderr)
    api.login(account, password)
    del password
    server_id = hashlib.sha256(api.server.encode("utf-8")).hexdigest()[:16]
    state_dir = args.state_dir / server_id
    identity = load_or_create(state_dir, account)
    public = public_bytes(identity)
    try:
        published = api.lookup_key(account)
    except PeerKeyUnavailable:
        published = None
    if published is not None and published != public:
        raise ValueError("local key differs from the uploaded key; use the original state directory")
    if published is None:
        api.upload_key(public)
    return api, account, identity, state_dir


# ----- Look: black ink on paper -----------------------------------------------------
# Everything visual is CSS over MonsterUI's base theme plus three Google Fonts; the only
# JavaScript is htmx (polling and partial swaps). Security states are drawn in ink, not
# colour: a filled badge for the hybrid suite, a dashed one for the legacy suite, rubber
# stamps for trust, so they still read on a monochrome print or to a colour-blind user.

INK, PAPER = "#111111", "#f2f2f2"

CSS = f"""
:root {{ --ink:{INK}; --paper:{PAPER}; --display:'Rye', serif; --condensed:'League Gothic', 'Oswald', sans-serif; --type:'Courier Prime', 'Courier New', monospace; }}
html, body {{ background: var(--paper) !important; color: var(--ink) !important; font-family: var(--type); }}
body::before {{ content:''; position: fixed; inset: 0; pointer-events: none; opacity: .07; filter: url(#grain); background: var(--ink); z-index: 0; mix-blend-mode: multiply; }}
.reel {{ position: relative; z-index: 1; max-width: 1180px; margin: 0 auto; padding: 1.5rem 1.25rem 3rem; }}
.card {{ border: 4px solid var(--ink); border-radius: 18px; padding: 1.1rem 1.3rem; background: var(--paper); box-shadow: 8px 8px 0 var(--ink); }}
.card.flat {{ box-shadow: none; border-width: 3px; }}
.title {{ font-family: var(--display); font-size: clamp(2.2rem, 6vw, 4rem); line-height: .95; margin: 0; text-transform: uppercase; }}
.sub {{ font-family: var(--condensed); font-size: clamp(1rem, 2.6vw, 1.4rem); letter-spacing: .12em; text-transform: uppercase; margin: .3rem 0 0; }}
.meta {{ font-family: var(--condensed); letter-spacing: .14em; text-transform: uppercase; font-size: .85rem; }}
.meta.lg {{ font-size: 1.1rem; }}
.rule {{ display:block; width: 100%; height: 14px; }}
.nav a, .nav span {{ color: var(--ink); text-decoration: none; border-bottom: 3px solid transparent; font-family: var(--condensed); font-size: 1.15rem; letter-spacing: .12em; text-transform: uppercase; margin-right: 1.4rem; }}
.nav a:hover, .nav .on {{ border-bottom-color: var(--ink); }}
.nav .on {{ background: var(--ink); color: var(--paper); padding: 0 .4rem; }}
.badge {{ display:inline-flex; align-items:center; gap:.35rem; border: 3px solid var(--ink); border-radius: 999px; padding: .05rem .6rem; font-family: var(--condensed); letter-spacing: .12em; text-transform: uppercase; font-size: .9rem; white-space: nowrap; }}
.badge.fill {{ background: var(--ink); color: var(--paper); }}
.badge.dashed {{ border-style: dashed; }}
.badge.faint {{ opacity: .55; border-width: 2px; }}
.hex {{ font-family: var(--type); word-break: break-all; font-size: .85rem; letter-spacing: .04em; background: repeating-linear-gradient(45deg, transparent 0 6px, rgba(17,17,17,.06) 6px 7px); padding: .25rem .5rem; border: 2px dashed var(--ink); display:inline-block; }}
.hex.fp {{ white-space: nowrap; word-break: normal; }}
.btn {{ font-family: var(--condensed); letter-spacing: .14em; text-transform: uppercase; font-size: 1rem; background: var(--ink); color: var(--paper); border: 3px solid var(--ink); border-radius: 12px; padding: .35rem 1rem; cursor: pointer; box-shadow: 3px 3px 0 var(--paper), 3px 3px 0 3px var(--ink); line-height: 1.3; }}
.btn:hover {{ background: var(--paper); color: var(--ink); }}
.btn.ghost {{ background: var(--paper); color: var(--ink); box-shadow: none; }}
.btn.ghost:hover {{ background: var(--ink); color: var(--paper); }}
.btn.sm {{ font-size: .85rem; padding: .15rem .6rem; border-width: 2px; box-shadow: none; }}
input.field, textarea.field {{ width: 100%; font-family: var(--type); font-size: .95rem; border: 3px solid var(--ink); border-radius: 10px; padding: .55rem .8rem; background: var(--paper); color: var(--ink); }}
input.field:focus, textarea.field:focus {{ outline: none; box-shadow: 4px 4px 0 var(--ink); }}
table.ledger {{ width: 100%; border-collapse: collapse; font-family: var(--type); font-size: .9rem; }}
table.ledger th {{ font-family: var(--condensed); letter-spacing: .12em; text-transform: uppercase; text-align: left; border-bottom: 4px solid var(--ink); padding: .5rem .4rem; font-weight: 400; font-size: 1.05rem; }}
table.ledger td {{ border-bottom: 2px solid var(--ink); padding: .55rem .4rem; vertical-align: top; }}
table.ledger tr.me td {{ background: rgba(17,17,17,.06); }}
.peer {{ display:block; border: 3px solid var(--ink); border-radius: 12px; padding: .5rem .7rem; margin-bottom: .5rem; color: var(--ink); text-decoration: none; background: var(--paper); }}
.peer:hover {{ box-shadow: 4px 4px 0 var(--ink); }}
.peer.on {{ background: var(--ink); color: var(--paper); }}
.peer.on .badge {{ border-color: var(--paper); }}
.peer.on .badge.fill {{ background: var(--paper); color: var(--ink); }}
.timeline {{ display:flex; flex-direction:column; gap:.6rem; margin-top: 1rem; min-height: 12rem; }}
.msg {{ max-width: 78%; border: 3px solid var(--ink); border-radius: 14px; padding: .45rem .8rem; background: var(--paper); font-family: var(--type); white-space: pre-wrap; word-break: break-word; }}
.msg.in {{ align-self: flex-start; border-bottom-left-radius: 2px; }}
.msg.out {{ align-self: flex-end; background: var(--ink); color: var(--paper); border-bottom-right-radius: 2px; }}
.msg.out .meta {{ color: var(--paper); opacity: .8; }}
.note .meta {{ margin-right:.5rem; }}
.msg .meta {{ display:block; font-size: .72rem; opacity: .75; margin-bottom: .15rem; }}
.note {{ align-self: center; max-width: 92%; font-family: var(--condensed); letter-spacing: .08em; text-transform: uppercase; font-size: .9rem; text-align:center; padding: .2rem .8rem; }}
.note.established {{ border: 3px solid var(--ink); border-radius: 999px; }}
.note.receipt, .note.system {{ opacity: .6; }}
.note.warning {{ border: 3px dashed var(--ink); border-radius: 10px; }}
.note.error {{ border: 4px double var(--ink); border-radius: 10px; background: rgba(17,17,17,.08); }}
.notice {{ border: 4px double var(--ink); border-radius: 14px; padding: .9rem 1.1rem; margin: .8rem 0; background: rgba(17,17,17,.06); }}
.notice h4 {{ font-family: var(--display); font-size: 1.5rem; margin: 0 0 .4rem; text-transform: uppercase; }}
.stamp {{ display:inline-block; transform: rotate(-5deg); vertical-align: middle; }}
.row {{ display:flex; gap:.6rem; align-items:center; flex-wrap:wrap; }}
.between {{ display:flex; gap:.6rem; align-items:center; justify-content:space-between; flex-wrap:wrap; }}
.grid {{ display:grid; grid-template-columns: 1fr; gap: 1.2rem; margin-top: 1.2rem; }}
@media (min-width: 820px) {{ .grid {{ grid-template-columns: 17rem 1fr; }} }}
.memo {{ font-family: var(--type); line-height: 1.5; }}
.footer {{ margin-top: 3rem; font-family: var(--condensed); letter-spacing: .14em; text-transform: uppercase; font-size: .8rem; text-align: center; display:flex; gap: 1rem; justify-content:center; align-items:center; opacity: .7; }}
.footer a, .footer button {{ color: var(--ink); background: none; border: none; cursor: pointer; font: inherit; letter-spacing: inherit; text-transform: inherit; }}
.footer a:hover, .footer button:hover {{ text-decoration: underline; }}
@keyframes blink {{ 0%, 92%, 100% {{ transform: scaleY(1); }} 96% {{ transform: scaleY(.08); }} }}
.eye {{ transform-origin: center; animation: blink 5.5s infinite; }}
.htmx-request .spin {{ animation: spin 1s linear infinite; }} @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
"""


# ----- Rendering ------------------------------------------------------------------

def build_app(inbox, loop):
    """Create the FastHTML app over an `Inbox` and a `ProtocolLoop`."""
    from fasthtml.common import (
        H1,
        H2,
        H3,
        H4,
        A,
        Beforeware,
        Button,
        Div,
        Form,
        Input,
        Link,
        Meta,
        P,
        RedirectResponse,
        Span,
        Style,
        Table,
        Tbody,
        Td,
        Textarea,
        Th,
        Thead,
        Title,
        Tr,
        fast_app,
    )
    from fasthtml.svg import Circle, Defs, Ellipse, FeTurbulence, Filter, G, Path, Rect, Svg, Text
    from monsterui.all import Theme, UkIcon

    # Hosted mode (deploy/): a login page guards everything when a password hash is set.
    # Locally there is no login; the page is bound to 127.0.0.1 only.
    password_hash = os.environ.get("JMESSAGE_UI_PASSWORD_HASH") or None
    footer_link = os.environ.get("JMESSAGE_FOOTER_LINK") or None
    footer_label = os.environ.get("JMESSAGE_FOOTER_LABEL") or "about"

    def require_login(req, sess):
        if password_hash and not sess.get("auth"):
            return RedirectResponse("/login", status_code=303)

    hdrs = [*Theme.zinc.headers(),
            Meta(name="viewport", content="width=device-width, initial-scale=1"),
            Meta(name="robots", content="noindex"),
            Link(rel="preconnect", href="https://fonts.googleapis.com"),
            Link(rel="stylesheet", href="https://fonts.googleapis.com/css2?family=Rye&family=League+Gothic"
                 "&family=Courier+Prime:ital,wght@0,400;0,700;1,400&display=swap"),
            Style(CSS)]
    # The cookie secret comes from the environment in hosted mode; a random one otherwise, which
    # also stops fast_app from writing a `.sesskey` file into the submission directory.
    app, rt = fast_app(hdrs=hdrs, pico=False,
                       secret_key=os.environ.get("JMESSAGE_SECRET_KEY") or secrets.token_hex(32),
                       sess_https_only=bool(os.environ.get("JMESSAGE_HTTPS")),
                       before=Beforeware(require_login, skip=[r"/login", r"/favicon\.ico"]))
    core = loop.runtime.client

    # ----- SVG furniture -----

    def grain_defs():
        return Svg(Defs(Filter(FeTurbulence(type="fractalNoise", baseFrequency="0.9", numOctaves="2",
                                            stitchTiles="stitch"), id="grain")),
                   width="0", height="0", style="position:absolute")

    def wobbly_rule():
        return Svg(Path(d="M2 7 C 60 2, 120 12, 180 7 S 300 2, 360 7 S 480 12, 540 7 S 660 2, 720 7 "
                          "S 840 12, 900 7 L 958 7", stroke=INK, stroke_width="4", fill="none",
                        stroke_linecap="round"),
                   viewBox="0 0 960 14", preserveAspectRatio="none", cls="rule")

    def mascot(size=120):
        """Rubber-hose envelope with a wax seal and pie-cut eyes, holding a key. Inline SVG."""
        return Svg(
            # envelope body and flap
            Rect(x="30", y="60", width="140", height="96", rx="10", fill=PAPER, stroke=INK, stroke_width="6"),
            Path(d="M30 66 L100 118 L170 66", fill="none", stroke=INK, stroke_width="6", stroke_linejoin="round"),
            # wax seal where the flap closes
            Circle(cx="100", cy="118", r="20", fill=INK),
            Circle(cx="100", cy="118", r="11", fill="none", stroke=PAPER, stroke_width="3"),
            # eyes on the flap (pie-cut pupils)
            Circle(cx="78", cy="84", r="13", fill=PAPER, stroke=INK, stroke_width="5"),
            Circle(cx="122", cy="84", r="13", fill=PAPER, stroke=INK, stroke_width="5"),
            G(Path(d="M78 84 L78 75 A9 9 0 1 1 70 88 Z", fill=INK), cls="eye"),
            G(Path(d="M122 84 L122 75 A9 9 0 1 1 114 88 Z", fill=INK), cls="eye"),
            # noodle arms and gloves
            Path(d="M32 120 C 4 128, 4 160, 30 162", stroke=INK, stroke_width="7", fill="none", stroke_linecap="round"),
            Path(d="M168 120 C 196 128, 196 160, 170 162", stroke=INK, stroke_width="7", fill="none", stroke_linecap="round"),
            Ellipse(cx="30", cy="166", rx="13", ry="10", fill=PAPER, stroke=INK, stroke_width="5"),
            Ellipse(cx="170", cy="166", rx="13", ry="10", fill=PAPER, stroke=INK, stroke_width="5"),
            # the key in the right glove
            G(Circle(cx="176", cy="150", r="9", fill="none", stroke=INK, stroke_width="5"),
              Path(d="M183 156 L198 171 M191 164 L196 159 M195 168 L200 163", stroke=INK, stroke_width="5",
                   stroke_linecap="round")),
            # feet
            Path(d="M80 158 L72 176 M88 160 L86 178 M120 158 L128 176 M112 160 L114 178", stroke=INK,
                 stroke_width="6", stroke_linecap="round"),
            viewBox="0 0 200 190", width=str(size), height=str(size), role="img",
            aria_label="Cartoon envelope with a wax seal, holding a key")

    def stamp(text, ok=True, width=200):
        """Rotated rubber stamp. Solid frame = good news, dashed = something to look at."""
        return Span(Svg(
            Rect(x="4", y="4", width="312", height="72", rx="12", fill="none", stroke=INK, stroke_width="6",
                 stroke_dasharray="0" if ok else "14 8"),
            Rect(x="14", y="14", width="292", height="52", rx="8", fill="none", stroke=INK, stroke_width="2"),
            Text(text, x="160", y="52", text_anchor="middle", font_family="'League Gothic', 'Oswald', sans-serif",
                 font_size="34", letter_spacing="4", fill=INK),
            viewBox="0 0 320 80", width=str(width), height=str(width // 4), opacity="0.92"), cls="stamp")

    # ----- small pieces -----

    def when(ts):
        return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else ""

    def date_of(unix):
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(unix)) if unix else "—"

    def hx(target="#conv-body"):
        return {"hx_target": target, "hx_swap": "outerHTML"}

    def suite_badge(conv, short=False):
        if conv is not None and conv.suite == JM2:
            return Span(UkIcon("shield-check", height=14, width=14),
                        "JM2 · hybrid" if short else "JM2 · hybrid X25519 + ML-KEM-768 · AES-256-GCM",
                        cls="badge fill")
        if conv is not None and conv.suite == JM1:
            return Span(UkIcon("shield-alert", height=14, width=14),
                        "JM1 · LEGACY" if short else "JM1 · LEGACY · X25519 only · AES-CBC + HMAC",
                        cls="badge dashed")
        return Span("no session", cls="badge faint")

    def trust_mark(conv, short=False):
        """What the user has decided about this peer's key, as a stamp or badge."""
        if conv is None or conv.fingerprint is None:
            return Span("key not fetched", cls="badge faint")
        if conv.key_changed:
            return stamp("KEY CHANGED", ok=False, width=140 if short else 200)
        if conv.verified:
            return stamp("VERIFIED", ok=True, width=120 if short else 170)
        return Span(UkIcon("circle-help", height=14, width=14), "NOT verified", cls="badge dashed")

    def fingerprint_block(conv):
        peer = conv.peer
        if conv.fingerprint is None:
            text = conv.fingerprint_error or "fingerprint not fetched yet"
            return P(UkIcon("key-round", height=14, width=14), f" {peer}: {text}", cls="meta")
        if conv.verified:
            stamp_text = "in an earlier run" if conv.verified_at == 0.0 else f"at {when(conv.verified_at)}"
            words = P(f"verified by you {stamp_text}: you compared this value with {peer} out of band.",
                      cls="memo", style="font-size:.9rem")
            action = Button("remove mark", hx_post=f"/unverify?peer={quote(peer)}", cls="btn ghost sm", **hx())
        else:
            words = P("NOT verified: the directory key is unauthenticated (spec §5). A signature "
                      "under it only proves the server handed out this key.", cls="memo", style="font-size:.9rem")
            action = Button("I compared it out of band: mark verified",
                            hx_post=f"/verify?peer={quote(peer)}&fp={quote(conv.fingerprint)}",
                            cls="btn sm", **hx())
        return Div(Div(Span(UkIcon("key-round", height=16, width=16), f" {peer}'s fingerprint", cls="meta"),
                       Span(conv.fingerprint, cls="hex fp"), cls="row", style="margin-top:.6rem"),
                   Div(trust_mark(conv), action, cls="row", style="margin-top:.4rem"), words)

    def key_change_alert(conv):
        if not conv.key_changed:
            return None
        old, new = conv.key_changed
        peer = conv.peer
        return Div(
            Div(UkIcon("triangle-alert", height=28, width=28), H4(f"{peer}'s directory key CHANGED"), cls="row"),
            P("The identity key the server publishes for this user is not the one you saw before. "
              "Either they re-registered, or someone else now holds this account name. "
              "Your verified mark has been cleared.", cls="memo"),
            P(Span("was ", cls="meta"), Span(old, cls="hex fp"), Span(" now ", cls="meta"), Span(new, cls="hex fp"),
              cls="row"),
            Div(Button("Reset trust (abandon sessions with this peer)",
                       hx_post=f"/reset-trust?peer={quote(peer)}", cls="btn sm", **hx()),
                Button("I understand, continue unverified",
                       hx_post=f"/ack-key-change?peer={quote(peer)}", cls="btn ghost sm", **hx()),
                cls="row", style="margin-top:.6rem"),
            cls="notice", role="alert")

    ICONS = {"in": "message-circle", "out": "send", "receipt": "check-check", "established": "lock",
             "warning": "triangle-alert", "error": "circle-x", "system": "info"}

    def entry_view(e):
        meta = [when(e.ts)]
        if e.seq is not None and e.kind == "in":
            meta.append(f"#{e.seq}")
        if e.kind == "out":
            meta.append({"queued": "queued until a session is established",
                         "sent": "handed to the server", "failed": "not sent"}[e.status])
        head = Span(UkIcon(ICONS.get(e.kind, "info"), height=12, width=12), " ", " · ".join(meta), cls="meta")
        if e.kind in ("in", "out"):
            return Div(head, e.text, cls=f"msg {e.kind}")
        label = f"{e.kind.upper()} · " if e.kind in ("warning", "error") else ""
        return Div(head, Span(label + e.text, style="text-transform:none;letter-spacing:0;"
                              "font-family:var(--type)"), cls=f"note {e.kind}")

    def conv_body(conv):
        """The polled part of a conversation: security header + timeline."""
        peer = conv.peer
        return Div(
            Div(Div(H3(peer, cls="title", style="font-size:2rem"), suite_badge(conv), cls="between"),
                P(f"session {conv.sid[:8]}…" if conv.sid else
                  "no session yet; sending text starts a handshake (§6.9)", cls="meta"),
                fingerprint_block(conv),
                key_change_alert(conv),
                Div(Button("New handshake", hx_post=f"/handshake?peer={quote(peer)}", cls="btn sm", **hx()),
                    Button("Refresh fingerprint", hx_post=f"/fingerprint?peer={quote(peer)}",
                           cls="btn ghost sm", **hx()),
                    cls="row", style="margin-top:.8rem"),
                cls="card flat"),
            Div(*[entry_view(e) for e in conv.entries[-200:]], cls="timeline"),
            id="conv-body", hx_get=f"/conv/{quote(peer)}", hx_trigger="every 2s", hx_swap="outerHTML")

    def compose(peer):
        return Form(
            Textarea(name="text", placeholder=f"message to {peer} (up to 4096 UTF-8 bytes)", rows=2,
                     cls="field"),
            Input(type="hidden", name="peer", value=peer),
            Button(UkIcon("send", height=16, width=16), " Send", cls="btn", style="align-self:flex-end"),
            hx_post="/send", **hx(),
            **{"hx-on::after-request": "if(event.detail.successful) this.reset()"},
            cls="row", style="margin-top:1rem;align-items:flex-end")

    def sidebar(snap, selected):
        convs = snap["conversations"]
        rows = []
        for name in sorted(n for n, c in convs.items() if c.opened):
            c = convs[name]
            flags = []
            if c.key_changed:
                flags.append(UkIcon("triangle-alert", height=16, width=16))
            if c.verified:
                flags.append(UkIcon("badge-check", height=16, width=16))
            if c.unread:
                flags.append(Span(str(c.unread), cls="badge fill"))
            rows.append(A(Div(Span(name, style="font-weight:700"), Div(*flags, cls="row"), cls="between"),
                          Div(suite_badge(c, short=True), style="margin-top:.3rem"),
                          href=f"/?peer={quote(name)}", cls="peer on" if name == selected else "peer"))
        if not rows:
            rows.append(P("No conversations yet. Pick someone in the directory, or type a name.",
                          cls="memo", style="font-size:.9rem"))
        others = len([u for u in snap["users"] if u != snap["account"]])
        new = Form(Input(name="peer", placeholder="username", required=True, pattern="[a-z0-9_]{1,32}",
                         cls="field"), Button("Open", cls="btn sm"), method="get", action="/", cls="row",
                   style="margin-top:.8rem;flex-wrap:nowrap")
        return Div(H4("Conversations", cls="meta lg"), *rows,
                   A(UkIcon("book-user", height=16, width=16), f" Directory · {others} other users",
                     href="/directory", cls="meta", style="display:block;margin-top:1rem"),
                   new, id="peers", hx_get=f"/peers?peer={quote(selected or '')}", hx_trigger="every 5s",
                   hx_swap="outerHTML")

    def status(snap):
        items = [Span(UkIcon("user", height=16, width=16), f" you are {snap['account']}", cls="badge fill")]
        if snap["own_fingerprint"]:
            items.append(Span(Span("your fingerprint ", cls="meta"), Span(snap["own_fingerprint"], cls="hex fp"),
                              cls="row"))
        if snap["jm1_only"]:
            items.append(Span("--jm1-only: you OFFER only the legacy suite", cls="badge dashed"))
        parts = [Div(*items, cls="row")]
        if snap["transport_failure"]:
            parts.append(Div(H4("Transport failure"), P(f"The driver stopped (no automatic retry): "
                                                       f"{snap['transport_failure']}. Restart the service.",
                                                       cls="memo"), cls="notice", role="alert"))
        sys_entries = [entry_view(e) for e in snap["system"][-5:]]
        if sys_entries:
            parts.append(Div(*sys_entries, cls="timeline", style="min-height:0;margin-top:.5rem"))
        return Div(*parts, id="status", hx_get="/status", hx_trigger="every 5s", hx_swap="outerHTML")

    def footer(logged_in=True):
        items = []
        if footer_link:
            # Just an icon; the label is the hover text.
            items.append(A(UkIcon("book-marked", height=16, width=16), href=footer_link,
                           title=footer_label, aria_label=footer_label))
        if password_hash and logged_in:
            items.append(Form(Button("log out"), method="post", action="/logout"))
        return Div(*items, cls="footer")

    def masthead(active):
        tabs = [("Conversations", "/"), ("Directory", "/directory")]
        return Div(
            Div(Div(H1("JMessage", cls="title"),
                    P("End-to-end encrypted · every security fact on the record", cls="sub"),
                    style="flex:1 1 60%"),
                Div(mascot(130), style="flex:0 0 auto;align-self:center"),
                cls="between", style="align-items:flex-start"),
            wobbly_rule(),
            Div(*[Span(name, cls="on") if href == active else A(name, href=href) for name, href in tabs],
                cls="nav", style="margin:.6rem 0 1rem"))

    def shell(title, active, *content, logged_in=True):
        return (Title(title), Div(grain_defs(), masthead(active), *content, footer(logged_in), cls="reel"))

    # ----- pages -----

    def page(selected):
        snap = inbox.snapshot()
        conv = snap["conversations"].get(selected) if selected else None
        if conv:
            main = Div(conv_body(conv), compose(selected))
        else:
            main = Div(H2("Nothing selected", cls="sub"),
                       P("Pick a conversation on the left, open the directory to browse every "
                         "registered user and their key, or type a username.", cls="memo"), cls="card")
        return shell("JMessage", "/", status(snap), Div(sidebar(snap, selected), main, cls="grid"))

    def directory_table(snap):
        convs, directory = snap["conversations"], snap["directory"]
        me = snap["account"]
        rows = []
        for name in sorted(set(snap["users"]) | set(directory)):
            d = directory.get(name, {})
            c = convs.get(name)
            if name == me:
                fp = Span(snap["own_fingerprint"] or "—", cls="hex fp")
                trust = Span("this is you", cls="badge fill")
                actions = ""
            else:
                fp = Span(c.fingerprint, cls="hex fp") if c and c.fingerprint else Span(
                    (c.fingerprint_error if c else None) or d.get("key_error") or "not fetched", cls="meta")
                trust = trust_mark(c, short=True)
                actions = Div(A("Open", href=f"/?peer={quote(name)}", cls="btn sm",
                                style="text-decoration:none"),
                              Button("Handshake", hx_post=f"/handshake?peer={quote(name)}&back=directory",
                                     cls="btn ghost sm", **hx("#directory")),
                              cls="row", style="flex-wrap:nowrap")
            idpk = d.get("idpk")
            key_cell = (Span(idpk[:12] + "…", title=idpk, cls="hex", style="font-size:.75rem") if idpk
                        else Span("—", cls="meta"))
            rows.append(Tr(Td(Span(name, style="font-weight:700"),
                              Div(suite_badge(c, short=True), style="margin-top:.2rem") if c and c.suite else ""),
                           Td(date_of(d.get("created"))), Td(date_of(d.get("last_seen"))),
                           Td(fp), Td(key_cell), Td(trust), Td(actions),
                           cls="me" if name == me else ""))
        refreshed = snap["directory_refreshed"]
        head = Div(Div(H2("Directory", cls="sub"),
                       P(f"{len(rows)} registered users · GET /users and GET /keys/<user> (spec §4.3) · "
                         f"{'refreshed ' + when(refreshed) if refreshed else 'not fetched yet'}", cls="meta")),
                   Form(Button(UkIcon("refresh-cw", height=16, width=16, cls="spin"), " Refresh directory",
                               cls="btn sm"), hx_post="/directory/refresh", **hx("#directory")),
                   cls="between")
        table = Table(Thead(Tr(Th("User"), Th("Registered"), Th("Last seen"), Th("Fingerprint (§5)"),
                               Th("idPK"), Th("Trust"), Th(""))),
                      Tbody(*rows), cls="ledger") if rows else P("No users listed yet.", cls="memo")
        note = P("The server hands out these keys unauthenticated. A fingerprint you have not compared "
                 "with its owner out of band identifies nobody; the stamps record what you decided, and a "
                 "change in a key you had verified is flagged everywhere.", cls="memo",
                 style="font-size:.85rem;margin-top:.8rem")
        return Div(head, table, note, id="directory", hx_get="/directory/table", hx_trigger="every 10s",
                   hx_swap="outerHTML", cls="card", style="overflow-x:auto")

    def directory_page():
        snap = inbox.snapshot()
        return shell("JMessage · directory", "/directory", status(snap),
                     Div(directory_table(snap), style="margin-top:1.2rem"))

    def login_page(error=None):
        return shell("JMessage · log in", None,
                     Div(Div(mascot(110), style="float:right;margin:-.5rem -.5rem 0 .5rem"),
                         H2("Log in", cls="sub"),
                         P("This client holds a real JMessage account and its identity key. "
                           "Log in to use it.", cls="memo"),
                         Div(P(error, cls="memo"), cls="notice", role="alert") if error else None,
                         Form(Input(type="password", name="password", placeholder="password", required=True,
                                    autofocus=True, cls="field"),
                              Button("Log in", cls="btn"), method="post", action="/login", cls="row",
                              style="flex-wrap:nowrap;margin-top:.8rem"),
                         cls="card", style="max-width:34rem;margin:2rem auto 0"),
                     logged_in=False)

    # ----- routes -----

    def valid_peer(value):
        try:
            return username(value)
        except ValueError as exc:
            inbox.note_system(f"invalid username {value!r}: {exc}", kind="error")
            return None

    def open_conversation(peer):
        inbox.conv(peer, open=True)
        inbox.mark_read(peer)
        loop.wants_fingerprint(peer)

    @rt("/login", methods=["get"])
    def get():
        if not password_hash:
            return RedirectResponse("/", status_code=303)
        return login_page()

    @rt("/login", methods=["post"])
    def post(sess, password: str = ""):
        if not password_hash:
            return RedirectResponse("/", status_code=303)
        if not check_password(password, password_hash):
            time.sleep(1.0)              # the reverse proxy rate-limits; this just blunts guessing
            return login_page("wrong password")
        sess["auth"] = True
        return RedirectResponse("/", status_code=303)

    @rt("/logout", methods=["post"])
    def post(sess):  # noqa: F811
        sess.clear()
        return RedirectResponse("/login" if password_hash else "/", status_code=303)

    @rt("/", methods=["get"])
    def get(peer: str = ""):  # noqa: F811
        selected = valid_peer(peer) if peer else None
        if selected:
            open_conversation(selected)
        return page(selected)

    @rt("/directory", methods=["get"])
    def get():  # noqa: F811
        return directory_page()

    @rt("/directory/table", methods=["get"])
    def get():  # noqa: F811
        return directory_table(inbox.snapshot())

    @rt("/directory/refresh", methods=["post"])
    def post():  # noqa: F811
        loop.submit("directory", loop.refresh_directory)
        time.sleep(0.3)
        return directory_table(inbox.snapshot())

    @rt("/conv/{peer}", methods=["get"])
    def get(peer: str):  # noqa: F811
        peer = valid_peer(peer)
        if peer is None:
            return Div(id="conv-body")
        inbox.mark_read(peer)
        return conv_body(inbox.conv(peer, open=True) and inbox.snapshot()["conversations"][peer])

    @rt("/peers", methods=["get"])
    def get(peer: str = ""):  # noqa: F811
        return sidebar(inbox.snapshot(), peer or None)

    @rt("/status", methods=["get"])
    def get():  # noqa: F811
        return status(inbox.snapshot())

    def action_then_conv(peer, label, fn, back=None):
        loop.submit(label, fn)
        time.sleep(0.15)       # give the protocol thread a moment so the reply shows the result
        if back == "directory":
            return directory_table(inbox.snapshot())
        return conv_body(inbox.snapshot()["conversations"][peer])

    @rt("/send", methods=["post"])
    def post(peer: str, text: str = ""):  # noqa: F811
        peer = valid_peer(peer)
        if peer is None:
            return Div(id="conv-body")
        try:
            encode_text(text)                    # same §7.1 pre-check as client.py dispatch
        except ValueError as exc:
            inbox.note_system(str(exc), peer=peer, kind="error")
            return conv_body(inbox.snapshot()["conversations"][peer])
        inbox.note_outgoing(peer, text)
        return action_then_conv(peer, "send_text", lambda: loop.runtime.call(
            core.send_text, peer, text, peer=peer))

    @rt("/handshake", methods=["post"])
    def post(peer: str, back: str = ""):  # noqa: F811
        peer = valid_peer(peer)
        if peer is None:
            return Div(id="conv-body")
        inbox.conv(peer, open=True)
        return action_then_conv(peer, "start_handshake", lambda: loop.runtime.call(
            core.start_handshake, peer, peer=peer), back=back)

    @rt("/fingerprint", methods=["post"])
    def post(peer: str):  # noqa: F811
        peer = valid_peer(peer)
        if peer is None:
            return Div(id="conv-body")
        inbox.conv(peer, open=True)
        return action_then_conv(peer, "fingerprint", lambda: loop.runtime.call(
            loop._fingerprint, peer, peer=peer))

    @rt("/verify", methods=["post"])
    def post(peer: str, fp: str):  # noqa: F811
        peer = valid_peer(peer)
        if peer is None:
            return Div(id="conv-body")
        if not inbox.mark_verified(peer, fp):
            inbox.note_system("fingerprint changed while you were looking; not marked",
                              peer=peer, kind="warning")
        return conv_body(inbox.snapshot()["conversations"][peer])

    @rt("/unverify", methods=["post"])
    def post(peer: str):  # noqa: F811
        peer = valid_peer(peer)
        if peer is None:
            return Div(id="conv-body")
        inbox.clear_verified(peer)
        return conv_body(inbox.snapshot()["conversations"][peer])

    @rt("/ack-key-change", methods=["post"])
    def post(peer: str):  # noqa: F811
        peer = valid_peer(peer)
        if peer is None:
            return Div(id="conv-body")
        inbox.acknowledge_key_change(peer)
        return conv_body(inbox.snapshot()["conversations"][peer])

    @rt("/reset-trust", methods=["post"])
    def post(peer: str):  # noqa: F811
        peer = valid_peer(peer)
        if peer is None:
            return Div(id="conv-body")
        inbox.acknowledge_key_change(peer)
        inbox.note_system("reset_peer_trust requested (Appendix B hook in protocol.py)",
                          peer=peer)
        return action_then_conv(peer, "reset_peer_trust", lambda: loop.runtime.call(
            core.reset_peer_trust, peer, peer=peer))

    return app


# ----- Entry point ------------------------------------------------------------------

def main(argv=None):
    if (argv if argv is not None else sys.argv[1:]) == ["--hash-password"]:
        print(hash_password(getpass.getpass("UI password to hash: ")))
        return 0
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--server", required=True, help="course HTTPS URL or loopback HTTP URL")
    parser.add_argument("--username", required=True)
    parser.add_argument("--register", action="store_true", help="create the account before login")
    parser.add_argument("--password-file", type=Path, help="otherwise prompt without echo")
    parser.add_argument("--state-dir", type=Path, default=Path(".jmessage"))
    parser.add_argument("--jm1-only", action="store_true", help="initiate in compatibility mode")
    parser.add_argument("--poll-interval", type=float, default=2)
    parser.add_argument("--no-auto-poll", action="store_true")
    parser.add_argument("--port", type=int, default=8010, help="loopback port for the web UI")
    args = parser.parse_args(argv)
    if not 1 <= args.poll_interval <= 5:
        parser.error("--poll-interval must be between 1 and 5 seconds")
    try:
        api, account, identity, state_dir = connect(args)
        from protocol import Client
        inbox = Inbox(account, trust_file=state_dir / f"{account}.ui-trust.json")
        runtime = Runtime(api, account, inbox.apply)
        runtime.client = Client(account, identity, api.lookup_key, runtime.emit, time.monotonic,
                                jm1_only=args.jm1_only)
        inbox.apply({"type": "ready", "username": account, "jm1_only": args.jm1_only})
        loop = ProtocolLoop(runtime, inbox, poll_interval=args.poll_interval,
                            auto_poll=not args.no_auto_poll)
        app = build_app(inbox, loop)
        loop.start()
        import uvicorn
        print(f"JMessage web UI for {account}: http://127.0.0.1:{args.port}", flush=True)
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning",
                    proxy_headers=True, forwarded_allow_ips="127.0.0.1")
        return 0
    except ImportError as exc:
        print(f"Missing UI dependency ({exc}). Install with: uv sync --extra ui", file=sys.stderr)
        return 1
    except TransportError as exc:
        print(f"Stopped: {exc}. No automatic retry was attempted.", file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        print(f"Setup error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
