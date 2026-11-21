# AI usage note

I used Claude Code; Fable for most of it... had to change to Opus for part 2,3, and 4.
Not by choice but rather because of the (restrictive) safeguards on Fable.

I followed the .mds instructions for AI usage, delegated what could be delegated
(once I had explained the workings) and wrote what I had to write myself. 
Maintained a conversationl-style dialogue with the models for feedback on my own 
understanding, explanations on the system, and code.

I verified the handshake worked (I do have a UI at jhu.nymo.finance so I tested over there), 
verified my code was correct, and the code the AI wrote.

I learned I had a misconception on what the padding was supposed to be doing and corrected
it accordingly. I generated the initial padding functions myself. No AI assistance and you 
can see my attempt at the corresponding .py. 

So my thoughs on the padding where we setup a random byte from 1-16 (that was not the last
non-padded byte) and we then would read out and remove the padding by "popping all equal
bytes from the end to the back".

Padding (as I thought it worked):

XY YZ (say 14/16 bytes where there, so just missing two padding bytes) 04 04 <- (random byte that was not the same as YZ)

Removing the padding (as I thought it worked):

P__ = XY YZ ... 04 04 

for x in P__ if x == 04
  P__.pop(x) # remove this value accordingly.

And padding is well.... the padding. The actual value of the bytes is supposed to be the
same as the number of padded bytes themselves.

AS CLAUDE PUTS IT (THIS is is what it states happened):
Claude corrections / AI contributions (factual record)

Part 0 — padding
- I wrote pkcs7_pad/pkcs7_unpad myself, no AI; padding_first_attempt.py is my unaided attempt. Claude only explained the concept after I had a misconception about what padding was (I thought padding used a random non-matching byte; corrected to "N bytes each equal to N").

I wrote receive, send_text, and the FINISH handler myself, and did the Part 0 warmup without generated code.

Part 1 — client
- I wrote the review-critical core myself: receive, send_text, _seal, _on_finish.
- Claude wrote the remaining handlers as helpers that call my code, after mine existed: _open (at my explicit request), _on_control, _on_reject, _send_hello, _abort.
- Claude built the web UI, the test harnesses (test_records, test_handlers, test_webui), and packaging/deploy glue.
- I verified the handshake end-to-end through my own UI; Claude ran the check suites (warmup, review_eligible, client_smoke — all pass).

Parts 2/3 — exercises
- I wrote recover_byte and its CBC derivation comment myself (several drafts; Claude gave only symptom-level hints — "no loop here," "that's forged_prev not prev_block" — never the expression).
- Claude wrote the attack plumbing after I explained each attack: downgrade, recover, experiment, and helpers (_corrupt_ek, _padding_oracle, _recover_block).
- Claude ran the exercises; Part 2 negotiation: pass, Part 3 recovery: pass, chain both pass.

Written work
- I wrote written.md (Part 4) and exercises/README.md myself. Claude critiqued drafts — flagged factual errors (I had the ML-KEM encapsulate/decapsulate roles reversed; I'd called AES-GCM "post-quantum" when the PQC is in the handshake) and gaps — and I revised. Claude did not write any graded answer.

---