"""Checks for the extra-credit web UI: the Inbox reducer and the rendered pages.

Run from starter/:  python -m unittest tests.test_webui -v
These need the optional UI dependencies (uv sync --extra ui); the rendering
tests are skipped without them. No protocol code is exercised here: the
`Client` is replaced by a stub, because the UI must work from events alone.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ui_state import Inbox

FP_A = "AA BB CC DD EE 00 11 22 33 44"
FP_B = "99 88 77 66 55 44 33 22 11 00"


class InboxChecks(unittest.TestCase):

    def test_established_sets_suite_and_drains_queued(self):
        box = Inbox("alice")
        box.note_outgoing("bob", "hi")
        self.assertEqual(box.conv("bob").entries[-1].status, "queued")
        box.apply({"type": "established", "peer": "bob", "sid": "00" * 16, "suite": 1})
        c = box.conv("bob")
        self.assertEqual(c.suite, 1)
        self.assertEqual(c.entries[0].status, "sent")
        box.note_outgoing("bob", "again")
        self.assertEqual(c.entries[-1].status, "sent")

    def test_message_receipt_warning_error_land_in_conversation(self):
        box = Inbox("alice")
        box.apply({"type": "message", "peer": "bob", "sid": "00" * 16, "seq": 3, "text": "yo"})
        box.apply({"type": "receipt", "peer": "bob", "sid": "00" * 16, "seq": 0})
        box.apply({"type": "warning", "peer": "bob", "message": "peer asked for a resend"})
        box.apply({"type": "error", "peer": None, "message": "no peer"})
        kinds = [e.kind for e in box.conv("bob").entries]
        self.assertEqual(kinds, ["in", "receipt", "warning"])
        self.assertEqual(box.conv("bob").unread, 1)
        self.assertEqual(box.system[-1].text, "no peer")

    def test_verify_only_current_value(self):
        box = Inbox("alice")
        self.assertFalse(box.mark_verified("bob", FP_A))        # nothing fetched yet
        box.set_fingerprint("bob", FP_A)
        self.assertFalse(box.mark_verified("bob", FP_B))        # stale value
        self.assertTrue(box.mark_verified("bob", FP_A))
        self.assertTrue(box.conv("bob").verified)

    def test_key_change_clears_verified_and_alerts(self):
        box = Inbox("alice")
        box.set_fingerprint("bob", FP_A)
        box.mark_verified("bob", FP_A)
        box.set_fingerprint("bob", FP_B)
        c = box.conv("bob")
        self.assertFalse(c.verified)
        self.assertEqual(c.key_changed, (FP_A, FP_B))
        self.assertEqual(c.entries[-1].kind, "error")
        self.assertIn("CHANGED", c.entries[-1].text)
        box.set_fingerprint("bob", FP_B)                 # same value again: alert stays
        self.assertEqual(c.key_changed, (FP_A, FP_B))
        box.acknowledge_key_change("bob")
        self.assertIsNone(c.key_changed)
        self.assertFalse(c.verified)

    def test_verified_mark_persists_and_change_after_restart_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            trust = Path(tmp) / "t.json"
            box = Inbox("alice", trust_file=trust)
            box.set_fingerprint("bob", FP_A)
            box.mark_verified("bob", FP_A)
            again = Inbox("alice", trust_file=trust)
            again.set_fingerprint("bob", FP_A)
            self.assertTrue(again.conv("bob").verified)
            third = Inbox("alice", trust_file=trust)
            third.set_fingerprint("bob", FP_B)
            self.assertFalse(third.conv("bob").verified)
            self.assertEqual(third.conv("bob").key_changed, (FP_A, FP_B))
            fourth = Inbox("alice", trust_file=trust)
            fourth.set_fingerprint("bob", FP_B)
            self.assertFalse(fourth.conv("bob").verified)   # the stale mark was removed


try:
    import fasthtml  # noqa: F401
    import monsterui  # noqa: F401
    from starlette.testclient import TestClient
    HAVE_UI = True
except ImportError:
    HAVE_UI = False


class _StubClient:
    """Stands in for protocol.Client: the UI may only call these public methods."""
    def __init__(self):
        self.calls = []

    def fingerprint(self, peer=None):
        self.calls.append(("fingerprint", peer))
        return FP_A if peer else FP_B

    def start_handshake(self, peer):
        self.calls.append(("start_handshake", peer))

    def send_text(self, peer, text):
        self.calls.append(("send_text", peer, text))

    def reset_peer_trust(self, peer):
        self.calls.append(("reset_peer_trust", peer))


class _StubRuntime:
    def __init__(self, inbox):
        self.client = _StubClient()
        self.account = "alice"
        self.api = None
        self.inbox = inbox

    def call(self, method, *args, peer=None):
        return method(*args)


class _InlineLoop:
    """Runs submitted actions immediately on the test thread."""
    def __init__(self, inbox):
        self.runtime = _StubRuntime(inbox)
        self.inbox = inbox
        self.labels = []

    def submit(self, label, fn):
        self.labels.append(label)
        fn()

    def wants_fingerprint(self, peer):
        pass

    def _fingerprint(self, peer):
        self.inbox.set_fingerprint(peer, self.runtime.client.fingerprint(peer))

    def refresh_directory(self):
        self.inbox.apply({"type": "users", "users": [
            {"username": "alice", "created": 1700000000, "lastSeen": 1700000100},
            {"username": "bob", "created": 1700000000, "lastSeen": 1700000200}]})
        self.inbox.set_directory_key("bob", "QUJDREVGR0g=")
        self._fingerprint("bob")


@unittest.skipUnless(HAVE_UI, "UI dependencies not installed (uv sync --extra ui)")
class RenderChecks(unittest.TestCase):

    def setUp(self):
        import webui
        self.inbox = Inbox("alice")
        self.loop = _InlineLoop(self.inbox)
        self.app = webui.build_app(self.inbox, self.loop)
        self.http = TestClient(self.app)

    def test_jm1_and_jm2_are_visibly_distinguished(self):
        self.inbox.apply({"type": "established", "peer": "bob", "sid": "ab" * 16, "suite": 1})
        self.inbox.apply({"type": "established", "peer": "carol", "sid": "cd" * 16, "suite": 2})
        bob = self.http.get("/conv/bob").text
        carol = self.http.get("/conv/carol").text
        self.assertIn("LEGACY", bob)
        self.assertNotIn("LEGACY", carol)
        self.assertIn("hybrid", carol)
        self.assertIn("abababab", bob)

    def test_message_text_is_escaped_and_shown_only_from_events(self):
        self.inbox.apply({"type": "message", "peer": "bob", "sid": "00" * 16, "seq": 1,
                          "text": "<script>alert(1)</script>"})
        html = self.http.get("/conv/bob").text
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_warning_and_error_appear_in_the_conversation(self):
        self.inbox.apply({"type": "warning", "peer": "bob", "message": "RESEND requested for #4"})
        self.inbox.apply({"type": "error", "peer": "bob", "message": "handshake aborted: bad sig"})
        html = self.http.get("/conv/bob").text
        self.assertIn("RESEND requested for #4", html)
        self.assertIn("handshake aborted: bad sig", html)
        self.assertIn("WARNING", html)
        self.assertIn("ERROR", html)

    def test_fingerprint_verify_flow_and_key_change(self):
        self.inbox.set_fingerprint("bob", FP_A)
        html = self.http.get("/conv/bob").text
        self.assertIn(FP_A, html)
        self.assertIn("NOT verified", html)
        html = self.http.post("/verify", params={"peer": "bob", "fp": FP_A}).text
        self.assertIn("verified by you", html)
        self.assertNotIn("NOT verified", html)
        # The directory now serves a different key: the alert appears, the mark is gone.
        self.inbox.set_fingerprint("bob", FP_B)
        html = self.http.get("/conv/bob").text
        self.assertIn("<h4", html)                        # the prominent alert heading
        self.assertIn("directory key CHANGED", html)
        self.assertIn("continue unverified", html)
        self.assertIn("NOT verified", html)
        self.assertNotIn("verified by you", html)
        html = self.http.post("/ack-key-change", params={"peer": "bob"}).text
        self.assertNotIn("continue unverified", html)     # alert dismissed ...
        self.assertIn("directory key CHANGED", html)      # ... but the timeline keeps the record
        self.assertIn("NOT verified", html)

    def test_actions_go_through_the_loop_and_public_client_methods_only(self):
        self.http.post("/send", data={"peer": "bob", "text": "hello"})
        self.http.post("/handshake", params={"peer": "bob"})
        self.http.post("/reset-trust", params={"peer": "bob"})
        self.assertEqual(self.loop.labels, ["send_text", "start_handshake", "reset_peer_trust"])
        calls = self.loop.runtime.client.calls
        self.assertIn(("send_text", "bob", "hello"), calls)
        self.assertIn(("start_handshake", "bob"), calls)
        self.assertIn(("reset_peer_trust", "bob"), calls)
        self.assertEqual(self.inbox.conv("bob").entries[0].text, "hello")
        self.assertEqual(self.inbox.conv("bob").entries[0].status, "queued")

    def test_bad_username_and_oversized_text_are_rejected_before_the_client(self):
        self.http.post("/send", data={"peer": "Bob!", "text": "x"})
        self.http.post("/send", data={"peer": "bob", "text": "é" * 2049})
        self.assertEqual(self.loop.labels, [])
        self.assertTrue(any(e.kind == "error" for e in self.inbox.system))
        self.assertTrue(any(e.kind == "error" for e in self.inbox.conv("bob").entries))

    def test_front_page_and_sidebar_render(self):
        self.inbox.apply({"type": "users", "users": ["bob", "alice", "carol"]})
        self.inbox.apply({"type": "ready", "username": "alice", "jm1_only": True})
        html = self.http.get("/", params={"peer": "bob"}).text
        self.assertIn("jm1-only", html)
        self.assertIn("message to bob", html)
        self.assertIn("Send", html)
        self.assertIn("2 other users", html)             # the directory link counts everyone but me
        self.assertNotIn(">carol<", html)                # unopened users are not conversations ...
        self.assertIn("carol", self.http.get("/directory").text)   # ... but are in the directory

    def test_directory_lists_users_keys_fingerprints_and_trust(self):
        self.inbox.apply({"type": "users", "users": [
            {"username": "alice", "created": 1700000000, "lastSeen": 1700000100},
            {"username": "bob", "created": 1700000000, "lastSeen": 1700000200},
            {"username": "dave"}, "not a dict either", 42]})
        self.assertEqual(self.inbox.users, ["alice", "bob", "dave"])
        self.inbox.set_directory_key("bob", "QUJDREVGR0hJSktMTU5PUA==")
        self.inbox.set_fingerprint("bob", FP_A)
        self.inbox.set_directory_key("dave", None, error="no key uploaded")
        self.inbox.fingerprint_unavailable("dave", "no key uploaded")
        html = self.http.get("/directory").text
        self.assertIn("3 registered users", html)
        self.assertIn("this is you", html)
        self.assertIn(FP_A, html)
        self.assertIn('title="QUJDREVGR0hJSktMTU5PUA=="', html)   # full idPK on hover
        self.assertIn("NOT verified", html)
        self.assertIn("no key uploaded", html)
        self.assertIn('href="/?peer=bob"', html)
        self.assertEqual(self.inbox.open_peers(), [])             # browsing opens nothing
        # Verified mark and key change show up here too.
        self.inbox.mark_verified("bob", FP_A)
        self.assertIn("VERIFIED", self.http.get("/directory/table").text)
        self.inbox.set_fingerprint("bob", FP_B)
        self.assertIn("KEY CHANGED", self.http.get("/directory/table").text)

    def test_directory_refresh_and_handshake_go_through_the_loop(self):
        html = self.http.post("/directory/refresh").text
        self.assertEqual(self.loop.labels, ["directory"])
        self.assertIn("QUJDREVGR0g=", html)
        self.assertIn(FP_A, html)
        html = self.http.post("/handshake", params={"peer": "bob", "back": "directory"}).text
        self.assertIn(("start_handshake", "bob"), self.loop.runtime.client.calls)
        self.assertIn('id="directory"', html)              # stays on the directory
        self.assertEqual(self.inbox.open_peers(), ["bob"])  # a handshake opens the conversation


@unittest.skipUnless(HAVE_UI, "UI dependencies not installed (uv sync --extra ui)")
class HostedModeChecks(unittest.TestCase):
    """With JMESSAGE_UI_PASSWORD_HASH set, every page needs the login cookie."""

    def setUp(self):
        import webui
        self.env = mock.patch.dict(os.environ, {
            "JMESSAGE_UI_PASSWORD_HASH": webui.hash_password("open sesame"),
            "JMESSAGE_FOOTER_LINK": "/transparency",
            "JMESSAGE_FOOTER_LABEL": "about this site",
            "JMESSAGE_SECRET_KEY": "k" * 64})
        self.env.start()
        self.inbox = Inbox("alice")
        self.loop = _InlineLoop(self.inbox)
        self.http = TestClient(webui.build_app(self.inbox, self.loop))

    def tearDown(self):
        self.env.stop()

    def test_password_hashing_roundtrip(self):
        import webui
        encoded = webui.hash_password("pw")
        self.assertTrue(encoded.startswith("pbkdf2_sha256$"))
        self.assertTrue(webui.check_password("pw", encoded))
        self.assertFalse(webui.check_password("pw2", encoded))
        self.assertFalse(webui.check_password("pw", "garbage"))

    def test_everything_redirects_to_login_until_authenticated(self):
        for path in ("/", "/conv/bob", "/status", "/peers"):
            r = self.http.get(path, follow_redirects=False)
            self.assertEqual((path, r.status_code), (path, 303))
            self.assertEqual(r.headers["location"], "/login")
        r = self.http.post("/send", data={"peer": "bob", "text": "hi"}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.loop.labels, [])          # nothing reached the protocol thread
        r = self.http.post("/login", data={"password": "nope"})
        self.assertIn("wrong password", r.text)
        r = self.http.post("/login", data={"password": "open sesame"}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        html = self.http.get("/").text
        self.assertIn("Conversations", html)
        self.assertIn('href="/transparency"', html)
        self.assertIn('title="about this site"', html)      # icon-only link, label on hover
        self.assertNotIn(">about this site<", html)
        self.http.post("/logout")
        self.assertEqual(self.http.get("/", follow_redirects=False).status_code, 303)

    def test_login_page_has_the_ledger_footer_too(self):
        html = self.http.get("/login").text
        self.assertIn('href="/transparency"', html)
        self.assertNotIn("log out", html)

    def test_wrong_method_is_refused(self):
        self.http.post("/login", data={"password": "open sesame"})
        self.assertEqual(self.http.get("/send").status_code, 405)
        self.assertEqual(self.http.get("/logout").status_code, 405)


class LocalModeChecks(unittest.TestCase):
    """Without the hash there is no login page and /login just bounces home."""

    @unittest.skipUnless(HAVE_UI, "UI dependencies not installed")
    def test_no_login_locally(self):
        import webui
        with mock.patch.dict(os.environ, {"JMESSAGE_UI_PASSWORD_HASH": ""}):
            http = TestClient(webui.build_app(Inbox("alice"), _InlineLoop(Inbox("alice"))))
            self.assertEqual(http.get("/").status_code, 200)
            self.assertEqual(http.get("/login", follow_redirects=False).status_code, 303)


if __name__ == "__main__":
    unittest.main()
