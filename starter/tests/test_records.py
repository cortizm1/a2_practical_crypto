"""Record-layer harness against the spec's Appendix A vectors (test scaffolding, agent-written).

Run from starter/:  python -m unittest tests.test_records -v

It drives the student's `Client._seal(session, text_bytes) -> bytes` and
`Client._open(session, data)` directly, with sessions whose keys are the
Appendix A values, so every check compares against bytes the course published,
not against an answer key of ours. Checks skip (not fail) until both methods
exist. `receive`-level checks run once `receive` no longer raises
NotImplementedError.
"""

import os
import re
import unittest
from pathlib import Path
from unittest import mock

import jmessage_support.messages as spm
import protocol
from protocol import ESTABLISHED, Client, Session

SPEC = Path(__file__).resolve().parents[2] / "specification.md"


# ----- Appendix A parser -----

def _hex_after(block, name):
    """The hex value printed under `name:` (possibly several indented lines)."""
    m = re.search(rf"^{re.escape(name)}:\n((?:  .*\n)+)", block, re.MULTILINE)
    if not m:
        return None
    text = "".join(line.strip() for line in m.group(1).splitlines())
    return b"" if text == "(empty)" else bytes.fromhex(text)


def load_vectors(suite):
    spec = SPEC.read_text(encoding="utf-8")
    start = spec.index("### A.1" if suite == spm.JM1 else "### A.2")
    end = spec.index("### A.2") if suite == spm.JM1 else spec.index("## Appendix B")
    section = spec[start:end]
    if suite == spm.JM1:
        keys = {k: _hex_after(section, k) for k in ("enc_IR", "mac_IR", "enc_RI", "mac_RI")}
    else:
        keys = {k: _hex_after(section, k) for k in ("k_IR", "k_RI")}
    records = []
    for m in re.finditer(r"^`(I->R|R->I)` seq (\d+):[^\n]*\n\n```\n(.*?)```", section, re.MULTILINE | re.DOTALL):
        direction, seq, block = m.group(1), int(m.group(2)), m.group(3)
        records.append({
            "direction": direction, "seq": seq,
            "plaintext": _hex_after(block, "plaintext"),
            "iv": _hex_after(block, "iv"), "nonce": _hex_after(block, "nonce"),
            "data": _hex_after(block, "DATA"), "receipt": _hex_after(block, "RECEIPT"),
        })
    assert len(records) == 8, f"expected 8 records for suite {suite}, parsed {len(records)}"
    sid = spm.parse_data(records[0]["data"]).sid
    return keys, sid, records


# ----- fixtures -----

class Harness:
    """One client per role with an established session holding the vector keys."""

    def __init__(self, suite):
        self.keys, self.sid, self.records = load_vectors(suite)
        self.suite = suite
        self.events = {"alice": [], "bob": []}
        self.clients = {}
        self.sessions = {}
        for me, peer, role in (("alice", "bob", "I"), ("bob", "alice", "R")):
            client = Client(me, os.urandom(32), lambda name: os.urandom(32),
                            self.events[me].append, lambda: 0.0)
            session = Session(sid=self.sid, peer=peer, role=role, state=ESTABLISHED,
                              peer_idpk=b"\0" * 32, hello=b"", started=0.0, suite=suite,
                              keys=dict(self.keys))
            client.sessions[self.sid] = session
            client.latest[peer] = self.sid
            self.clients[me], self.sessions[me] = client, session

    @staticmethod
    def who(direction):
        """(sender, receiver) usernames for a vector direction."""
        return ("alice", "bob") if direction == "I->R" else ("bob", "alice")

    def sends(self, who):
        return [e for e in self.events[who] if e["type"] == "send"]

    def messages(self, who):
        return [e for e in self.events[who] if e["type"] == "message"]


def _ready(client):
    return callable(getattr(client, "_seal", None)) and callable(getattr(client, "_open", None))


class _RecordChecks:
    suite = None

    def setUp(self):
        self.h = Harness(self.suite)
        if not _ready(self.h.clients["alice"]):
            self.skipTest("Client._seal / Client._open not written yet")

    # -- the vectors, byte for byte --

    def test_open_every_vector_delivers_text_and_receipts(self):
        for rec in self.h.records:
            sender, receiver = self.h.who(rec["direction"])
            client, session = self.h.clients[receiver], self.h.sessions[receiver]
            before = len(self.h.events[receiver])
            client._open(session, spm.parse_data(rec["data"]))
            new = self.h.events[receiver][before:]
            with self.subTest(direction=rec["direction"], seq=rec["seq"]):
                self.assertEqual([e["type"] for e in new], ["send", "message"],
                                 "expected exactly: RECEIPT sent, then the text delivered")
                self.assertEqual(new[0]["to"], sender)
                self.assertEqual(new[0]["body"], rec["receipt"])
                self.assertEqual(new[1]["text"], rec["plaintext"].decode("utf-8"))
                self.assertEqual(new[1]["seq"], rec["seq"])
                self.assertEqual(session.recv_seq, rec["seq"] + 1)

    def test_seal_every_vector_reproduces_data_bytes(self):
        for rec in self.h.records:
            sender, _ = self.h.who(rec["direction"])
            client, session = self.h.clients[sender], self.h.sessions[sender]
            with self.subTest(direction=rec["direction"], seq=rec["seq"]):
                if self.suite == spm.JM1:
                    # The IV is random by rule; pin the OS source to the vector's IV.
                    with mock.patch.object(protocol.os, "urandom", return_value=rec["iv"]):
                        body = client._seal(session, rec["plaintext"])
                else:
                    body = client._seal(session, rec["plaintext"])
                self.assertEqual(body, rec["data"])
                self.assertEqual(session.send_seq, rec["seq"] + 1)

    # -- the §7.2 outcomes --

    def _first(self):
        rec = self.h.records[0]
        sender, receiver = self.h.who(rec["direction"])
        return rec, self.h.clients[receiver], self.h.sessions[receiver], sender, receiver

    def test_tampered_record_gets_resend_and_seq_stays(self):
        rec, client, session, _sender, receiver = self._first()
        body = bytearray(rec["data"])
        body[-1] ^= 0x01                      # last byte: tag (JM2) or last CBC block (JM1)
        client._open(session, spm.parse_data(bytes(body)))
        sends = self.h.sends(receiver)
        self.assertEqual(len(sends), 1)
        self.assertEqual(sends[0]["body"], spm.encode_control(spm.T_RESEND, self.h.sid, rec["seq"]))
        self.assertEqual(self.h.messages(receiver), [])
        self.assertEqual(session.recv_seq, 0)

    def test_wrong_seq_and_duplicate_are_silent(self):
        rec0, rec1 = self.h.records[0], self.h.records[1]
        _, client, session, _, receiver = self._first()
        client._open(session, spm.parse_data(rec1["data"]))          # seq 1 before seq 0
        self.assertEqual(self.h.events[receiver], [])
        client._open(session, spm.parse_data(rec0["data"]))          # accepted
        n = len(self.h.events[receiver])
        client._open(session, spm.parse_data(rec0["data"]))          # duplicate: silent, no 2nd receipt
        self.assertEqual(len(self.h.events[receiver]), n)
        self.assertEqual(session.recv_seq, 1)

    def test_short_protected_is_silent(self):
        rec, client, session, _, receiver = self._first()
        parsed = spm.parse_data(rec["data"])
        for n in (0, 15, 31) if self.suite == spm.JM1 else (0, 15):
            client._open(session, spm.Data(parsed.sid, parsed.seq, parsed.protected[:n]))
        if self.suite == spm.JM1:                                     # 48 bytes but not a multiple of 16
            client._open(session, spm.Data(parsed.sid, parsed.seq, parsed.protected + b"\0" * 8))
        self.assertEqual(self.h.events[receiver], [])
        self.assertEqual(session.recv_seq, 0)

    def test_application_format_error_still_consumes_seq_and_receipts(self):
        # Invalid UTF-8 sealed by the peer (§7.2 step 4): local error, RECEIPT sent, no RESEND.
        sender, receiver = "alice", "bob"
        body = self.h.clients[sender]._seal(self.h.sessions[sender], b"\xff\xfe")
        client, session = self.h.clients[receiver], self.h.sessions[receiver]
        client._open(session, spm.parse_data(body))
        kinds = [e["type"] for e in self.h.events[receiver]]
        self.assertIn("error", kinds)
        self.assertNotIn("message", kinds)
        self.assertEqual([e["body"][0] for e in self.h.sends(receiver)], [spm.T_RECEIPT])
        self.assertEqual(session.recv_seq, 1)

    def test_round_trip_both_directions_with_fresh_text(self):
        for sender, receiver, text in (("alice", "bob", "x" * 4096), ("bob", "alice", "")):
            body = self.h.clients[sender]._seal(self.h.sessions[sender], text.encode())
            self.h.clients[receiver]._open(self.h.sessions[receiver], spm.parse_data(body))
            self.assertEqual(self.h.messages(receiver)[-1]["text"], text)


class JM1RecordChecks(_RecordChecks, unittest.TestCase):
    suite = spm.JM1

    def test_bad_padding_is_malformed_and_silent(self):
        # Flip a byte in the second-to-last ciphertext block: CBC garbles the last block's
        # plaintext, so its padding is (almost surely) invalid -> silent discard, not RESEND.
        rec, client, session, _, receiver = self._first()
        body = bytearray(rec["data"])
        body[-17] ^= 0x80
        client._open(session, spm.parse_data(bytes(body)))
        self.assertEqual(self.h.events[receiver], [])
        self.assertEqual(session.recv_seq, 0)


class JM2RecordChecks(_RecordChecks, unittest.TestCase):
    suite = spm.JM2


class ReceiveLevelChecks(unittest.TestCase):
    """Through the public entry point, once `receive` exists: DATA for an unknown sid, from the
    wrong sender, or to the wrong recipient is silent (§6.9); the vector still delivers."""

    def setUp(self):
        self.h = Harness(spm.JM2)
        client = self.h.clients["bob"]
        if not _ready(client):
            self.skipTest("Client._seal / Client._open not written yet")
        try:
            client.receive("nobody", "bob", b"\x7f")
        except NotImplementedError:
            self.skipTest("Client.receive not written yet")

    def test_envelope_and_session_gates(self):
        rec = self.h.records[0]
        bob = self.h.clients["bob"]
        bob.receive("mallory", "bob", rec["data"])                # wrong sender for this sid
        bob.receive("alice", "carol", rec["data"])                # not addressed to me
        other = spm.encode_data(os.urandom(16), 0, spm.parse_data(rec["data"]).protected)
        bob.receive("alice", "bob", other)                        # unknown sid
        self.assertEqual(self.h.events["bob"], [])
        bob.receive("alice", "bob", rec["data"])
        self.assertEqual([e["type"] for e in self.h.events["bob"]], ["send", "message"])
        bob.receive("alice", "bob", rec["receipt"])               # a RECEIPT must never be answered
        self.assertEqual(len(self.h.sends("bob")), 1)


if __name__ == "__main__":
    unittest.main()
