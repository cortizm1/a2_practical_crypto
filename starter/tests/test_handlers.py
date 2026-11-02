"""Checks for the agent-written handlers `_on_reject` (§6.8) and `_on_control` (§7.3).

Glue (AGENTS.md): drives two real Clients through the fixture Network and
asserts on emitted events and wire bytes only. The public run_checks groups do
not exercise REJECT or RESEND; the autograder rows "Signed REJECT and bounded
JM1 fallback" and "RECEIPT/RESEND state and cached records" do.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jmessage_support.messages as spm                       # noqa: E402
import protocol                                               # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from jmessage_support.codec import str8                       # noqa: E402
from jmessage_support.testing import Network                  # noqa: E402
from protocol import PENDING_REPLY, Client                    # noqa: E402


def pending_sid(client):
    (sid,) = [s.sid for s in client.sessions.values() if s.state == PENDING_REPLY]
    return sid


class RejectChecks(unittest.TestCase):
    def setUp(self):
        self.net = Network(names=("alice", "bob", "carol"))
        self.alice = self.net.attach("alice", Client)
        self.bob = self.net.attach("bob", Client)
        self.carol = self.net.attach("carol", Client)

    def start_and_drop_hello(self, jm1_only=False):
        """Alice queues text and starts a handshake; the HELLO never reaches Bob."""
        self.alice.jm1_only = jm1_only
        self.alice.send_text("bob", "hi bob")
        self.net.queue.clear()
        return pending_sid(self.alice)

    def test_hybrid_invalid_retries_once_with_jm1_and_delivers_queued_text(self):
        sid = self.start_and_drop_hello()
        self.bob._send_reject("alice", sid, spm.REASON_HYBRID_INVALID)
        self.net.pump()
        self.assertIn(sid, self.alice.retired)
        self.assertNotIn(sid, self.alice.sessions)
        est = self.net.matching("alice", "established")
        self.assertEqual([e["suite"] for e in est], [spm.JM1])
        retry = self.alice.sessions[est[0]["sid"]]
        self.assertTrue(retry.retry_used)
        self.assertEqual(retry.offered, (spm.JM1,))
        self.assertEqual(self.net.matching("bob", "message")[0]["text"], "hi bob")
        self.assertFalse(self.net.matching("alice", "error"))
        # the retry HELLO carried no ML-KEM key (§3: ek_I empty without JM2)
        hello = [b for (f, t, b) in self.net.wire if f == "alice" and b[0] == spm.T_HELLO][-1]
        self.assertEqual(spm.parse_hello(hello).suites, (spm.JM1,))
        self.assertEqual(spm.parse_hello(hello).ek, b"")

    def test_second_hybrid_invalid_aborts_and_returns_queued_text(self):
        sid = self.start_and_drop_hello()
        self.bob._send_reject("alice", sid, spm.REASON_HYBRID_INVALID)
        self.alice.receive("bob", "alice", self.net.queue.popleft()[2])     # first REJECT only
        self.net.queue.clear()                                              # drop the retry HELLO
        sid2 = pending_sid(self.alice)
        self.bob._send_reject("alice", sid2, spm.REASON_HYBRID_INVALID)
        self.net.pump()
        self.assertNotIn(sid2, self.alice.sessions)
        self.assertIn(sid2, self.alice.retired)
        errors = [e["message"] for e in self.net.matching("alice", "error")]
        self.assertTrue(any("no fallback left" in m for m in errors), errors)
        self.assertTrue(any("unsent" in m and "hi bob" in m for m in errors), errors)
        self.assertEqual(self.alice.queued.get("bob", []), [])

    def test_hybrid_invalid_on_a_jm1_only_offer_aborts(self):
        sid = self.start_and_drop_hello(jm1_only=True)
        self.bob._send_reject("alice", sid, spm.REASON_HYBRID_INVALID)
        self.net.pump()
        self.assertNotIn(sid, self.alice.sessions)
        self.assertTrue(self.net.matching("alice", "error"))
        self.assertFalse([b for (f, t, b) in self.net.wire if f == "alice" and b[0] == spm.T_HELLO][1:])

    def test_other_reason_aborts_with_error(self):
        sid = self.start_and_drop_hello()
        self.bob._send_reject("alice", sid, spm.REASON_NO_COMMON_SUITE)
        self.net.pump()
        self.assertNotIn(sid, self.alice.sessions)
        self.assertIn(sid, self.alice.retired)
        self.assertTrue(any("0x02" in e["message"] for e in self.net.matching("alice", "error")))

    def test_forged_or_misaddressed_reject_is_ignored_and_handshake_stays_pending(self):
        sid = self.start_and_drop_hello()
        signed = b"JMessage-2026 reject" + sid + bytes([spm.REASON_NO_COMMON_SUITE]) + str8("alice")
        forged = spm.encode_reject(sid, spm.REASON_NO_COMMON_SUITE, Ed25519PrivateKey.generate().sign(signed))
        self.alice.receive("bob", "alice", forged)                          # bad signature
        self.carol._send_reject("alice", sid, spm.REASON_NO_COMMON_SUITE)   # wrong sender, valid for carol
        self.net.pump()
        self.alice.receive("bob", "alice", b"\x04" + sid)                   # truncated
        self.assertEqual(self.alice.sessions[sid].state, PENDING_REPLY)
        self.assertFalse(self.net.matching("alice", "error"))
        self.assertEqual(len([b for (f, t, b) in self.net.wire if f == "alice"]), 1)  # only the HELLO


class ControlChecks(unittest.TestCase):
    def setUp(self):
        self.net = Network()
        self.alice = self.net.attach("alice", Client)
        self.bob = self.net.attach("bob", Client)
        self.alice.start_handshake("bob")
        self.net.pump()
        self.sid = self.net.matching("alice", "established")[0]["sid"]
        self.alice.send_text("bob", "first")
        self.net.pump()
        self.data = [b for (f, t, b) in self.net.wire if f == "alice" and b[0] == spm.T_DATA][0]

    def controls_sent_by(self, name):
        return [b for (f, t, b) in self.net.wire if f == name and b[0] in (spm.T_RECEIPT, spm.T_RESEND)]

    def test_receipt_reported_once_and_duplicates_change_nothing(self):
        self.assertEqual([e["seq"] for e in self.net.matching("alice", "receipt")], [0])
        receipt = spm.encode_control(spm.T_RECEIPT, self.sid, 0)
        self.alice.receive("bob", "alice", receipt)
        self.alice.receive("bob", "alice", receipt)
        self.assertEqual(len(self.net.matching("alice", "receipt")), 1)
        self.assertEqual(self.alice.sessions[self.sid].send_seq, 1)
        self.assertEqual(self.controls_sent_by("alice"), [])                 # never a control for a control

    def test_resend_replays_exact_cached_bytes_once_then_warns(self):
        before = len(self.net.wire)
        self.alice.receive("bob", "alice", spm.encode_control(spm.T_RESEND, self.sid, 0))
        sent = [b for (f, t, b) in self.net.wire[before:] if f == "alice"]
        self.assertEqual(sent, [self.data])                                  # same IV/tag, same seq
        self.assertEqual(self.alice.sessions[self.sid].send_seq, 1)          # no new seq allocated
        self.alice.receive("bob", "alice", spm.encode_control(spm.T_RESEND, self.sid, 0))
        self.assertEqual(len([b for (f, t, b) in self.net.wire[before:] if f == "alice"]), 1)
        self.assertTrue(any("not resent" in e["message"] for e in self.net.matching("alice", "warning")))
        self.assertEqual(self.controls_sent_by("alice"), [])
        # Bob can still open the replayed record exactly once (duplicate seq is silent)
        self.net.pump()
        self.assertEqual(len(self.net.matching("bob", "message")), 1)

    def test_control_for_unsent_seq_or_wrong_peer_or_pending_session_is_silent(self):
        n_events = len(self.net.events["alice"])
        self.alice.receive("bob", "alice", spm.encode_control(spm.T_RECEIPT, self.sid, 7))   # never sent
        self.alice.receive("bob", "alice", spm.encode_control(spm.T_RESEND, self.sid, 7))
        self.alice.receive("bob", "alice", spm.encode_control(spm.T_RECEIPT, os.urandom(16), 0))  # unknown sid
        self.assertEqual(len(self.net.events["alice"]), n_events)
        # a session still pending-reply accepts no control messages
        self.alice.jm1_only = True
        self.alice.start_handshake("bob")
        self.net.queue.clear()
        pend = pending_sid(self.alice)
        n_events = len(self.net.events["alice"])
        self.alice.receive("bob", "alice", spm.encode_control(spm.T_RECEIPT, pend, 0))
        self.assertEqual(len(self.net.events["alice"]), n_events)


if __name__ == "__main__":
    unittest.main()
