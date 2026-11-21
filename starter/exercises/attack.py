"""Your Parts 2 and 3 attacks. Fill in the entry points below.

The runner starts a fresh sandbox, calls `start` for you, and then calls one of
these functions with an `ExerciseAPI` object `api` (see API.md). You act as the
malicious relay: inspect the queue, deliver, drop, and inject protocol bodies.
You never see plaintext, keys, or any padding/MAC flag — only the wire messages
the bots emit and the limited status fields.

Copy this exercises/ directory into your client directory (your submission),
then run from the extracted kit, with <dir> that client directory:

    python run_exercises.py --submission <dir> --part 2 --output <dir>/run-part2
    python run_exercises.py --submission <dir> --part 3 --output <dir>/run-part3
    python run_exercises.py --submission <dir> --part chain --output <dir>/run-chain
    python run_exercises.py --submission <dir> --part experiment --output <dir>/run-exp

See EXERCISES.md for the task, the threat model, the evidence to submit, and the
resource limits. `recover_byte` is yours to write by hand (handout Revision 3).

Authorship (ai-usage.md): `downgrade`, `recover`, `experiment` and the helpers
were written with Claude (agent) after Carlos explained each attack; the one
cryptographic line, `recover_byte`, and its derivation comment are Carlos's own.
"""

from jmessage_reference._support.messages import (
    T_HELLO, T_DATA, T_RESEND, JM1, JM2,
    encode_hello, parse_hello, encode_data, parse_data, parse_reject,
    message_type,
)

BLOCK = 16                      # AES block size; JM1 CBC works one block at a time
MAC_LEN = 32                    # HMAC-SHA256 tag length, appended before padding


# ----- small relay helpers (glue) ------------------------------------------

def _queue_by_type(api, t, sender=None):
    """Return queued envelopes whose body has type `t` (and optional sender), in order."""
    out = []
    for env in api.queue():
        if env["body"] and message_type(env["body"]) == t:
            if sender is None or env["from"] == sender:
                out.append(env)
    return out


def _emitted_type(emitted, t):
    """True if any envelope the bot just emitted has message type `t`."""
    return any(e["body"] and message_type(e["body"]) == t for e in emitted)


def _corrupt_ek(hello_body):
    """Rebuild Alice's HELLO with a wrong-length ML-KEM key, same everything else.

    Same sid, same offered suites, same X25519 key; only the ek is changed to the
    wrong length. The responder still selects JM2 (the offer is unchanged) and
    then fails the §6.4 step-3 length check (len(ek) != 1184), emitting a
    *genuine* signed hybrid_invalid REJECT for this exact sid. We forge nothing.

    A same-length but all-zero ek does NOT work: an all-zero encoding is still a
    valid ML-KEM-768 key, so the responder would Encaps happily and send REPLY.
    The failure the responder reacts to is the length, which is why we drop a byte.
    """
    h = parse_hello(hello_body)
    return encode_hello(h.sid, h.suites, h.x_pub, h.ek[:-1])    # 1183 bytes: present, wrong length


# ----- Part 2 --------------------------------------------------------------

def downgrade(api) -> bytes:
    """Part 2. Make the two honest bots establish a JM1 session.

    The move does not touch Alice's offer (the transcript check would catch
    that; see `experiment`). Instead it abuses the fact that a §6.8 REJECT
    signature covers only `sid || reason || str8(I)`, never the HELLO. So:

      1. Capture Alice's real HELLO (sid_1, offer [JM2, JM1]); drop it so Bob
         never sees the genuine one.
      2. Inject to Bob the *same* HELLO with its ek_I zeroed. Bob still picks
         JM2, fails the ML-KEM check, and emits a genuine signed
         REJECT(sid_1, hybrid_invalid) — he signs it himself; we forge nothing.
      3. Deliver that REJECT to Alice. Her §6.8 fallback fires: she retires
         sid_1 and sends a fresh HELLO_2 offering JM1 only (same pinned Bob key).
      4. Relay HELLO_2 -> REPLY -> FINISH untouched. Both bots establish JM1 and
         neither sees anything amiss: Alice downgraded herself, believing Bob
         cannot do ML-KEM.

    Returns the 16-byte sid of the JM1 session. For a chained run we stop before
    handing Alice's secret DATA to Bob, leaving it for `recover`.
    """
    # Step 1: Alice's HELLO is already queued. Capture and drop it.
    hello1 = _queue_by_type(api, T_HELLO, sender="alice")[0]
    sid_1 = parse_hello(hello1["body"]).sid
    api.drop(hello1["id"])

    # Step 2: inject the ek-corrupted twin to Bob; he answers with a REJECT.
    emitted = api.inject("alice", "bob", _corrupt_ek(hello1["body"]))

    # Step 3: deliver Bob's REJECT to Alice; she emits HELLO_2 (JM1 only).
    reject = emitted[0]
    assert parse_reject(reject["body"]).sid == sid_1, "REJECT must name the original sid"
    api.inject("bob", "alice", reject["body"])

    # Step 4: drive the JM1 handshake to completion, relaying each message once.
    #   HELLO_2 (alice->bob) -> REPLY (bob->alice) -> FINISH (alice->bob) -> established.
    hello2 = _queue_by_type(api, T_HELLO, sender="alice")[0]
    sid_2 = parse_hello(hello2["body"]).sid
    api.drop(hello2["id"])
    emitted = api.inject("alice", "bob", hello2["body"])             # Bob -> REPLY
    reply = emitted[0]
    emitted = api.inject("bob", "alice", reply["body"])             # Alice -> FINISH
    finish = emitted[0]
    # Delivering FINISH establishes Bob's session and makes Alice drain her
    # queued secret as a DATA she emits (captured by the sandbox as the target).
    api.inject("alice", "bob", finish["body"])

    # Both bots are now on JM1 for sid_2. Leave Alice's secret DATA unaccepted by
    # Bob (do not deliver it), so a chained `recover` can probe sequence zero.
    st = api.status()
    assert st["negotiation"] and st["negotiation"]["suite"] == JM1, "expected JM1 established"
    return sid_2


# ----- Part 3 --------------------------------------------------------------

def recover_byte(prev_block: bytes, forged_prev: bytes, position: int) -> int:
    """Return the plaintext byte at `position` of the target block. WRITE THIS YOURSELF.

    This is the one piece of the attack you must write by hand, not generate
    (handout Revision 3, "Write this yourself"). Above it, add a two- or
    three-line comment deriving it from how CBC decryption works.

    `prev_block` is the genuine ciphertext block (or the IV) that precedes the
    target block in the record. `forged_prev` is the previous block you sent
    that made the oracle report valid padding, with the bytes after `position`
    already fixed to produce the matching padding value. Return the recovered
    plaintext byte (0-255).

    Your `recover` must call this for every byte it reports.
    """

    # P_real[position] = I[position] XOR prev_block[position]

    # we are running the attack on a byte to byte basis, 
    # increasing our fake padding as we figure out the bytes hence we compute our pad for our current position.
    pad = BLOCK - position
    # so our I[position] at our current fake pad
    recover_byte_ = forged_prev[position] ^ pad
    # needs to be xored against the previous element at said position (since that's the way CBC works... chaining up values computed)
    recover_byte_ = recover_byte_ ^ prev_block[position]

    return recover_byte_


def _padding_oracle(api, sid, seq, iv_block, target_block):
    """One probe. Inject IV'||target_block to Bob; RESEND => valid padding.

    §7.2: Bob CBC-decrypts, checks PKCS7 padding first. Bad padding is MALFORMED
    and silent; valid padding then fails the MAC and yields a RESEND. recv_seq
    never advances on either, so `seq` stays probeable across every query.
    """
    body = encode_data(sid, seq, iv_block + target_block)
    emitted = api.inject("alice", "bob", body)
    return _emitted_type(emitted, T_RESEND)


def _recover_block(api, sid, seq, prev_block, target_block):
    """Classic CBC padding-oracle recovery of one 16-byte block.

    For padding value `pad` (1..16) we fix the last `pad-1` forged bytes to make
    that many valid padding bytes, then sweep the byte at `position = BLOCK-pad`
    until the oracle accepts. That confirmed `forged_prev` is handed to the
    student's `recover_byte`, which returns the genuine plaintext byte.
    """
    inter = bytearray(BLOCK)        # inter[i] = AES_dec(target_block)[i], suite-independent
    plain = bytearray(BLOCK)
    for pad in range(1, BLOCK + 1):
        position = BLOCK - pad
        forged = bytearray(BLOCK)
        for i in range(position + 1, BLOCK):
            forged[i] = inter[i] ^ pad          # re-create known padding bytes
        hit = None
        for guess in range(256):
            forged[position] = guess
            if _padding_oracle(api, sid, seq, bytes(forged), target_block):
                # Guard against the pad=1 false positive (a trailing 0x02 0x02 ...):
                # perturb the byte before and require the oracle to still accept.
                if pad == 1 and position > 0:
                    probe = bytearray(forged)
                    probe[position - 1] ^= 0xFF
                    if not _padding_oracle(api, sid, seq, bytes(probe), target_block):
                        continue
                hit = guess
                break
        if hit is None:
            raise RuntimeError(f"oracle gave no valid padding for pad={pad}")
        inter[position] = hit ^ pad                                   # D(target)[position]
        plain[position] = recover_byte(prev_block, bytes(forged), position)   # YOURS
    return bytes(plain)


def recover(api, target) -> dict:
    """Part 3. Recover the plaintext of the captured JM1 record `target`.

    Walk the captured record block by block with the padding oracle, newest
    plaintext block first is unnecessary — CBC lets each block be attacked
    independently using its own preceding ciphertext block as `prev_block`.
    Strip the PKCS7 padding and the trailing 32-byte HMAC to get Alice's text.
    """
    data = parse_data(target["body"])
    sid, seq, protected = data.sid, data.seq, data.protected
    iv, ct = protected[:BLOCK], protected[BLOCK:]
    blocks = [ct[i:i + BLOCK] for i in range(0, len(ct), BLOCK)]

    recovered = {}                       # ciphertext-order index -> 16 plaintext bytes
    for idx, block in enumerate(blocks):
        prev = iv if idx == 0 else blocks[idx - 1]
        recovered[idx] = _recover_block(api, sid, seq, prev, block)

    padded = b"".join(recovered[i] for i in range(len(blocks)))
    plaintext = None
    pad = padded[-1] if padded else 0
    if 1 <= pad <= BLOCK and padded[-pad:] == bytes([pad]) * pad:
        body = padded[:-pad]                     # drop PKCS7 padding
        if len(body) >= MAC_LEN:
            plaintext = body[:-MAC_LEN]           # drop the trailing HMAC tag
    return {"plaintext": plaintext, "blocks": recovered}


# ----- Part 2 write-up diagnostic ------------------------------------------

def experiment(api) -> None:
    """Offer-stripping diagnostic: strip JM2 from Alice's HELLO and watch it fail.

    Bob accepts a HELLO that offers JM1 only and signs REPLY over TH_R built
    from the *modified* HELLO bytes he received. Alice then verifies sig_R using
    TH_R built from the HELLO bytes she *sent* (the original [JM2, JM1]); the two
    transcripts differ, her REPLY-signature check fails, and she aborts. This is
    why the real downgrade leaves the offer untouched and goes through REJECT.
    """
    hello = _queue_by_type(api, T_HELLO, sender="alice")[0]
    h = parse_hello(hello["body"])
    stripped = encode_hello(h.sid, (1,), h.x_pub, b"")      # JM1 only, no ek
    api.drop(hello["id"])
    emitted = api.inject("alice", "bob", stripped)          # Bob -> REPLY over modified HELLO
    for e in emitted:                                       # deliver REPLY to Alice
        if e["body"] and message_type(e["body"]) == 2:      # T_REPLY
            api.inject("bob", "alice", e["body"])           # Alice aborts at the TH_R check
