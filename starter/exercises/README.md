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
- The interventions I made, as a short sequence of relay operations:
- Evidence that **both** bots established JM1 (cite `result.json` /
  `transport-trace.jsonl`):
- **Offer-stripping experiment.** What I changed, what the responder did, and
  why the handshake failed at the transcript-verification step (name the check):

## Part 3 — record recovery

- The observable distinction I used as the oracle:
- A few representative probes and the responses they drew (not the whole log):
- Which sequence number my probes used, and why it stays usable:
- How I resolved the last-byte padding ambiguity:
- Recovered output, or the blocks I recovered and how far I got:
- Approximate query count:
- My `recover_byte`: a sentence on the CBC relation it computes (you wrote it):

## Security property and limits

- The security property that failed, in one or two sentences:
- The assumptions my attack needs (what the relay can do, what it cannot):
- The limits of my evidence (what a single run does and does not show):

## Interface, bot, or agent (Part 1 extra credit)

- Would the thing you built have shown the user the downgrade? If you built
  none, write "not applicable."
