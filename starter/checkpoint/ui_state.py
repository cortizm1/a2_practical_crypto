"""Event-to-screen state for the web UI (extra credit, handout Part 1).

What this file is for
---------------------
The `Client` in protocol.py reports everything through `emit`, and the driver
turns those into display dictionaries (jmessage_support/events.py). A UI has
to remember them: which peer has which session, what was said, what went
wrong, and what the user has decided to trust. `Inbox` is that memory. It is
a pure reducer: feed it display dicts and user actions, ask it for a
snapshot, and render the snapshot. No HTTP, no HTML, no threads of its own.

Where it sits

      Runtime.output(display dict)  --> Inbox.apply(event)
      protocol thread               --> Inbox.set_fingerprint(peer, value)
      web handlers (user clicks)    --> Inbox.note_outgoing / mark_verified / ...
      web handlers (render)         <-- Inbox.snapshot()

Zone: glue (AGENTS.md "Glue"). This module never sees keys, transcripts,
records or protocol bodies. It only sees what the core chose to emit, so by
construction it cannot show message text before the `message` event (the
extra-credit rule in the handout).

Security-state rules this module implements (the extra-credit criteria):

* the current session's suite per peer, so the UI can distinguish JM1 from JM2;
* the peer fingerprint as reported by `Client.fingerprint`, the user's
  "verified" mark, and the rule that a fingerprint change (= a directory key
  change) clears that mark and raises a prominent alert;
* warnings and errors attached to the conversation they concern.

The verified marks are persisted (peer -> fingerprint) so that restarting the
UI keeps them, and a key change after a restart is still detected: the stored
fingerprint is the value the user verified, not merely the last one seen.
"""

from __future__ import annotations

import json
import re
import threading
import time
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path

JM1, JM2 = 1, 2
USERNAME = re.compile(r"[a-z0-9_]{1,32}\Z")   # spec §3; the directory shows nothing else
SUITE_NAMES = {JM1: "JM1", JM2: "JM2"}


@dataclass
class Entry:
    """One line of a conversation timeline."""
    kind: str               # "in" | "out" | "receipt" | "established" | "warning" | "error" | "system"
    text: str
    ts: float
    seq: int | None = None
    sid: str | None = None  # hex, as displayed by the driver
    status: str = ""        # for "out": "queued" | "sent" | "failed"


@dataclass
class Conversation:
    peer: str
    entries: list = field(default_factory=list)
    suite: int | None = None        # suite of the most recently established session
    sid: str | None = None          # hex sid of that session
    fingerprint: str | None = None  # last value Client.fingerprint(peer) returned
    fingerprint_error: str | None = None
    verified: bool = False
    verified_at: float | None = None
    key_changed: tuple | None = None  # (old_fingerprint, new_fingerprint) until acknowledged
    unread: int = 0
    opened: bool = False            # shown in the sidebar: the user opened it or traffic arrived

    def add(self, entry):
        self.entries.append(entry)
        del self.entries[:-500]       # keep the timeline bounded


class Inbox:
    """Thread-safe reducer from display events and user actions to screen state."""

    def __init__(self, account, *, trust_file=None, clock=time.time):
        self.account = account
        self.clock = clock
        self.lock = threading.RLock()
        self.conversations: dict[str, Conversation] = {}
        self.users: list[str] = []
        self.directory: dict[str, dict] = {}   # username -> created/last_seen/idpk/fetched
        self.directory_refreshed: float | None = None
        self.own_fingerprint: str | None = None
        self.jm1_only = False
        self.ready = False
        self.transport_failure: str | None = None
        self.system: list[Entry] = []      # events with no peer
        self.trust_file = Path(trust_file) if trust_file else None
        self._verified_fps = self._load_trust()

    # ----- persistence of the user's verified marks -----

    def _load_trust(self):
        if not self.trust_file or not self.trust_file.is_file():
            return {}
        try:
            data = json.loads(self.trust_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}

    def _save_trust(self):
        if not self.trust_file:
            return
        self.trust_file.parent.mkdir(parents=True, exist_ok=True)
        self.trust_file.write_text(json.dumps(self._verified_fps, indent=1), encoding="utf-8")

    # ----- helpers -----

    def conv(self, peer, *, open=False):
        """The conversation record for `peer`, created on first use.

        A record exists for every user whose fingerprint was ever fetched (the
        directory does that for everyone), so key changes are detected for all
        of them; only `opened` ones appear in the conversation list.
        """
        with self.lock:
            if peer not in self.conversations:
                self.conversations[peer] = Conversation(peer=peer)
            c = self.conversations[peer]
            if open:
                c.opened = True
            return c

    def peers(self):
        with self.lock:
            return sorted(self.conversations)

    def open_peers(self):
        with self.lock:
            return sorted(p for p, c in self.conversations.items() if c.opened)

    # ----- display events from Runtime.output -----

    def apply(self, event):
        """Reduce one display dictionary (jmessage_support/events.display_event)."""
        kind = event.get("type")
        now = self.clock()
        with self.lock:
            if kind == "ready":
                self.ready = True
                self.jm1_only = bool(event.get("jm1_only"))
            elif kind == "sent":
                pass    # a protocol body was accepted by the server; the UI never sees which
            elif kind == "established":
                c = self.conv(event["peer"], open=True)
                c.suite, c.sid = event["suite"], event["sid"]
                c.add(Entry("established", f"session established with suite "
                            f"{SUITE_NAMES.get(c.suite, c.suite)}", now, sid=c.sid))
                for e in c.entries:
                    if e.kind == "out" and e.status == "queued":
                        e.status = "sent"      # §6.9: queued text is drained on establishment
            elif kind == "message":
                c = self.conv(event["peer"], open=True)
                c.add(Entry("in", event["text"], now, seq=event["seq"], sid=event["sid"]))
                c.unread += 1
            elif kind == "receipt":
                c = self.conv(event["peer"], open=True)
                c.add(Entry("receipt", f"peer acknowledged record #{event['seq']}", now,
                            seq=event["seq"], sid=event["sid"]))
            elif kind in ("warning", "error"):
                entry = Entry(kind, event.get("message", ""), now)
                peer = event.get("peer")
                if peer:
                    c = self.conv(peer, open=True)
                    c.add(entry)
                    if kind == "error":
                        for e in c.entries:
                            if e.kind == "out" and e.status == "queued":
                                e.status = "failed"
                else:
                    self.system.append(entry)
                    del self.system[:-100]
            elif kind == "users":
                self._set_users(event.get("users", []), now)
            elif kind == "fingerprint":
                if event.get("peer") == self.account:
                    self.own_fingerprint = event.get("value")
                else:
                    self.set_fingerprint(event["peer"], event["value"])

    # ----- directory (§4.3 GET /users and GET /keys/<user>) -----

    def _set_users(self, listing, now):
        """Accept the raw GET /users list (dicts) or plain usernames (client.py style)."""
        names = []
        for item in listing:
            if isinstance(item, str):
                name, created, seen = item, None, None
            elif isinstance(item, dict) and isinstance(item.get("username"), str):
                name = item["username"]
                created = item.get("created") if isinstance(item.get("created"), int) else None
                seen = item.get("lastSeen") if isinstance(item.get("lastSeen"), int) else None
            else:
                continue
            if not USERNAME.match(name):
                continue
            names.append(name)
            entry = self.directory.setdefault(name, {"idpk": None, "fetched": None,
                                                     "key_error": None})
            entry["created"], entry["last_seen"] = created, seen
        self.users = sorted(set(names))
        self.directory_refreshed = now

    def set_directory_key(self, peer, idpk_b64, error=None):
        """Record the raw directory key (base64 of idPK) as served, or why it was unavailable."""
        with self.lock:
            entry = self.directory.setdefault(peer, {"created": None, "last_seen": None})
            entry["idpk"] = idpk_b64
            entry["key_error"] = error
            entry["fetched"] = self.clock()

    # ----- fingerprints and trust -----

    def set_fingerprint(self, peer, value):
        """Record what Client.fingerprint(peer) returned; detect a directory key change."""
        with self.lock:
            c = self.conv(peer)
            c.fingerprint_error = None
            verified_fp = self._verified_fps.get(peer)
            previous = c.fingerprint or verified_fp
            if previous is not None and value != previous:
                c.key_changed = (previous, value)
                c.verified = False
                c.verified_at = None
                if verified_fp is not None:
                    self._verified_fps.pop(peer, None)
                    self._save_trust()
                c.add(Entry("error", f"{peer}'s directory key CHANGED: fingerprint was "
                            f"{previous}, is now {value}. Verified mark cleared.", self.clock()))
            c.fingerprint = value
            if c.key_changed is None:
                c.verified = verified_fp == value
                if c.verified and c.verified_at is None:
                    c.verified_at = 0.0     # verified in an earlier run

    def fingerprint_unavailable(self, peer, message):
        with self.lock:
            self.conv(peer).fingerprint_error = message

    def mark_verified(self, peer, fingerprint):
        """The user compared `fingerprint` out of band. Only the current value can be marked."""
        with self.lock:
            c = self.conv(peer)
            if c.fingerprint is None or fingerprint != c.fingerprint:
                return False
            c.verified, c.verified_at, c.key_changed = True, self.clock(), None
            self._verified_fps[peer] = fingerprint
            self._save_trust()
            c.add(Entry("system", f"you marked {peer}'s fingerprint as verified", self.clock()))
            return True

    def clear_verified(self, peer):
        with self.lock:
            c = self.conv(peer)
            c.verified, c.verified_at = False, None
            if self._verified_fps.pop(peer, None) is not None:
                self._save_trust()
            c.add(Entry("system", f"you removed the verified mark for {peer}", self.clock()))

    def acknowledge_key_change(self, peer):
        """The user saw the key-change alert and chose to continue (still unverified)."""
        with self.lock:
            c = self.conv(peer)
            c.key_changed = None
            c.add(Entry("system", f"you acknowledged {peer}'s key change; the new key is "
                        "NOT verified", self.clock()))

    # ----- user actions -----

    def note_outgoing(self, peer, text):
        """The user asked to send `text`. Status reflects §6.9: queued until a session exists."""
        with self.lock:
            c = self.conv(peer, open=True)
            status = "sent" if c.suite is not None else "queued"
            c.add(Entry("out", text, self.clock(), status=status))

    def note_system(self, text, peer=None, kind="system"):
        with self.lock:
            entry = Entry(kind, text, self.clock())
            if peer:
                self.conv(peer, open=True).add(entry)
            else:
                self.system.append(entry)

    def mark_read(self, peer):
        with self.lock:
            if peer in self.conversations:
                self.conversations[peer].unread = 0

    def transport_failed(self, message):
        with self.lock:
            self.transport_failure = message
            self.system.append(Entry("error", f"transport failure, driver stopped: {message}",
                                     self.clock()))

    # ----- rendering input -----

    def snapshot(self):
        """A deep copy for rendering, so handlers never hold the lock while building HTML."""
        with self.lock:
            return deepcopy({
                "account": self.account, "ready": self.ready, "jm1_only": self.jm1_only,
                "own_fingerprint": self.own_fingerprint, "users": list(self.users),
                "directory": dict(self.directory), "directory_refreshed": self.directory_refreshed,
                "transport_failure": self.transport_failure, "system": list(self.system),
                "conversations": dict(self.conversations),
            })
