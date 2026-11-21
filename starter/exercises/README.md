# Parts 2 and 3 — your explanation and evidence

Fill this in. It is graded separately from whether your attacks executed:
a clear account of a partial result earns partial credit, and a working attack
you cannot explain does not earn full marks. Keep it concise — a page or two.
Put the repair analysis in `written.md` (Part 4) and cross-reference it here
rather than repeating it.

## How to run my attacks

- Which parts are complete:
- Commands I ran (and which `run-*/result.json` backs each claim):

## Part 2 — downgrade

- Alice's original offer (the suites, in order):
JM2, JM1

- The interventions I made, as a short sequence of relay operations:
Message sent by Alice, server parses the message and sends an almost exact replica 
of the message to Bob but with a missing byte on the ML-KEM ephemeral public key.

- Evidence that **both** bots established JM1 (cite `result.json` /
  `transport-trace.jsonl`):
transport-trace.jsonl line 4-10. We sent a HELLO with len 1239, that was rejected by 
Bob. Alice attempted the fallback and succeeded, the established handshake with Bob
was then with the JM1.

- **Offer-stripping experiment.** What I changed, what the responder did, and
  why the handshake failed at the transcript-verification step (name the check):
Message sent by Alice, server parses the message and sends message to Bob but with a 
changed suite. Bob accepts. Alice gets bobs REPLY and notices something strange with the HELLO,
handshake aborted.
We can look at the transport-trace.jsonl for the experiment and notice how bob replied back (REPLY)
to keep the handshake going but ALICE silently discarded since the message had been tampered.

## Part 3 — record recovery

- The observable distinction I used as the oracle:
The fact that sending Bob a tampered message back to him with a padding error would silently discard, whereas
a tampered message with the right padding would throw back an ERROR.

- A few representative probes and the responses they drew (not the whole log):

{"op": 8835, "method": "POST", "path": "/adv/inject", "status": 200, "delivered_id": 8918, "injected": {"from": "alice", "to": "bob", "type": "DATA", "len": 57, "b64": "ECRN4iM7N+wMMSv3SRCpbjEAAAAAAAAAAKrRCt9YKYW2tXsc7jMnJSrWlfOi6ldZSqZ5SM1MNfSd", "id": 8918, "sid": "244de2233b37ec0c312bf74910a96e31", "seq": 0}, "emitted": []}
{"op": 8836, "method": "POST", "path": "/adv/inject", "status": 200, "delivered_id": 8919, "injected": {"from": "alice", "to": "bob", "type": "DATA", "len": 57, "b64": "ECRN4iM7N+wMMSv3SRCpbjEAAAAAAAAAAKvRCt9YKYW2tXsc7jMnJSrWlfOi6ldZSqZ5SM1MNfSd", "id": 8919, "sid": "244de2233b37ec0c312bf74910a96e31", "seq": 0}, "emitted": [{"from": "bob", "to": "alice", "type": "RESEND", "len": 25, "b64": "EiRN4iM7N+wMMSv3SRCpbjEAAAAAAAAAAA==", "id": 8920}]}
{"op": 8837, "method": "POST", "path": "/adv/inject", "status": 200, "delivered_id": 8921, "injected": {"from": "alice", "to": "bob", "type": "DATA", "len": 57, "b64": "ECRN4iM7N+wMMSv3SRCpbjEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC7wIXQXGbHF2f4TaRZqynM", "id": 8921, "sid": "244de2233b37ec0c312bf74910a96e31", "seq": 0}, "emitted": []}

- Which sequence number my probes used, and why it stays usable:
Sequence number stays usable because counter only goes up when we get a reply back from our peer... if messages are being dropped no way to realize this
with our current implementation.

- How I resolved the last-byte padding ambiguity:
By checking if it is the last byte, and if so (if pad == 1 and position > 0:)
we run a special case for it.

- Recovered output, or the blocks I recovered and how far I got:
"ECRN4iM7N+wMMSv3SRCpbjEAAAAAAAAAAB   d  Je7/3SkRXu2RV0FEo6YC7wIXQXGbHF2f4TaRZqynM"

full recovery, as per the .jsonl trace/results

- Approximate query count:
10879

- My `recover_byte`: a sentence on the CBC relation it computes (you wrote it):
It gets a byte and XORs it to go from our fake padding to the actual value by using the same bit (position) at the previous_block (CBC)

## Security property and limits

- The security property that failed, in one or two sentences:
- The assumptions my attack needs (what the relay can do, what it cannot):
- The limits of my evidence (what a single run does and does not show):

## Interface, bot, or agent (Part 1 extra credit)

- Would the thing you built have shown the user the downgrade? If you built
  none, write "not applicable."
Nope. UI would've not shown it as is.