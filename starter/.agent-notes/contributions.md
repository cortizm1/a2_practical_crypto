# Contribution log (agent-kept, private; not a graded deliverable)

Format per AGENTS.md: work item + zone; who specified/wrote what; labels
(concept explanation / example shown / implementation written / test written /
test run / prose drafted / prose critiqued / student text transcribed); who ran
checks; understanding check status; deferred walkthroughs.

## 2026-10-25 — session start (Claude Code)

- **Context:** first session with this agent. Earlier work (padding.py,
  utils.py, fingerprint/start_handshake drafts in protocol.py) is
  student-authored per git history (commits cdc8333..113378a); agent did not
  observe it. No earlier agent log exists.
- **Read:** handout.md, specification.md, AGENTS.md, README.md, all of
  jmessage_support/, protocol.py, padding.py, utils.py, client.py, tests/.
- **Test run (agent-run):** `check_environment.py` PASS (Python 3.13.12,
  cryptography 49.0.0, OpenSSL 4.0.1). `run_checks.py warmup` FAILED
  (3 failures, 8 errors) on the student's current padding.py.
- **Observed (not fixed, per Part 0 rule — padding_first_attempt.py does not
  exist yet):** pad byte value is random rather than N; pad length uses
  abs(len - block) so inputs longer than one block get the wrong length;
  empty input returns None; bad block sizes do not raise; the
  `function_logger_too` decorator drops the default `block_size` argument
  (TypeError on 1-arg calls) and swallows exceptions; unpad's backward scan
  accepts `..01 02` and `..00`.
- **Observed in protocol.py:** module-level test code at bottom runs on
  import; fingerprint hashes idSK || lookup-function instead of the §5
  label || idPK; `random.randbytes` is not a CSPRNG; encode_hello called
  with peer in the x_pub slot; nothing emitted/stored.
- **Teaching status:** no concept explanations yet; no understanding checks
  yet. Student asked to "discuss" before building.
- **Deadline noted:** late checkpoint cutoff Mon Oct 26, 9:00 am Eastern.
- **Next action:** student decides division of work (handout non-negotiables:
  Part 0 first attempt; `receive`, `send_text`, one handshake handler
  student-written) and saves padding_first_attempt.py before any padding
  debugging help.

## 2026-10-25 — second exchange

- Student reports a deadline extension to Wed Oct 28 for Part 1.
- Student stated the current padding.py is entirely pre-agent work. Agent
  copied it verbatim to padding_first_attempt.py (glue: file copy). No
  padding code has been changed by the agent.
- Agent restored `tools/anon-report.py` from starter-kit.zip (glue; it was
  missing from the working starter/ directory).
- Student questions this round (answered in chat, concept explanation only,
  no code written): why pad gets the whole message not a block; what kind
  of PRNG os.urandom is; where lookup_peer_key / emit / own public key /
  ephemeral X25519 key come from. Student proposed os.urandom for sids/IVs
  themselves (correct).
- Student requested: unify the two logging decorators into one that logs
  and re-raises (glue; agent will write after design is agreed).
- Division of work stated by student: agent writes code after discussing
  specs. Agent restated the handout non-negotiables (receive, send_text,
  one handshake handler) and recommended student-written fingerprint and
  JM1 record functions (teaching default).
- Understanding checks: none yet.

## 2026-10-25 — third exchange

- **Glue, implementation written by agent (student-requested):** replaced
  the two broken decorators in utils.py with one `logged` decorator
  (*args/**kwargs, functools.wraps, logs and re-raises; never swallows).
  Old names aliased so student files needed no edits. Removed the
  import-time `Client("pipipupu"...)` test calls from the bottom of
  protocol.py (student had confirmed they were scratch).
- **Test run (agent-run):** warmup still fails; probe after the fix shows
  every `pkcs7_pad` returning None (log: `len()` called on an int) and
  unpad accepting `..00`, `..11`, `..01 02`. Reported symptoms + log lines
  to student; no padding logic changed by agent.
- Student revised pad length to `len % block` (remainder, still wrong) and
  pad byte to `int(len(pad_length_))`; student did not answer the 33-byte
  prediction question. Agent re-asked.
- **Concept explanation (agent):** fingerprint uses the Ed25519 identity
  public key, not the X25519 example the student pasted; mapped the pasted
  HKDF snippet's salt/info/length placeholders to the §6.7 predicate.
- Understanding check: pending (33-byte prediction; fingerprint inputs).

## 2026-10-25 — fourth exchange

- Student answered the 33-byte prediction: 15 pad bytes, 48 total (correct
  count; value not stated). Student's `pad_lengther` still returns the
  remainder (33 -> 1), contradicting their own answer; agent pointed at
  the contradiction, did not supply the formula.
- **Test run (agent-run):** warmup 8 failures. pad now emits real bytes
  with value == count (fixed by student); count wrong for non-aligned
  input. unpad still accepts `..00`, `..11`, `..01 02`; empty/1-byte
  inputs return None because of the per-function except.
- Student's fingerprint description ("private key, whatever x25519 uses")
  is wrong: agent corrected to Ed25519 identity *public* key (concept
  explanation). Four fingerprint questions re-asked.
- Understanding check: 33-byte count answered independently; value and
  unpad conditions still pending.

## 2026-10-25 — fifth exchange

- **Test run (agent-run):** warmup 7 failures. `pkcs7_pad` is now correct
  for all probed lengths (student fixed the length rule independently
  after the contradiction was pointed out). Remaining: unpad accepts
  `..00`, `..11`, `..01 02`; empty/1-byte return None (swallowed); pad/unpad
  with block size 0/256 return None instead of ValueError.
- Fingerprint Q/A (student answers): Q1 correct on key + half; said
  private key is "for decryption" (agent corrected: Ed25519 private key
  signs). Q2 not answered (no derivation named); agent pointed at
  identity.public_bytes. Q3 mostly right; misconception that lookup goes
  through emit/runtime events (agent corrected: direct synchronous call;
  raises PeerKeyUnavailable). Q4 hash input and 10-byte truncation correct;
  display format not stated; asked what the label is (agent explained
  domain separation).
- Labels: concept explanation (signing vs decryption; domain separation;
  lookup path). No implementation written.

## 2026-10-25 — sixth exchange

- Student added `pad_checker(data, pad_digit)` (student-written). Agent
  reviewed (review only, no code written): called with one arg; `p`
  undefined; `padd_digit` typo; `p in data` is membership not range;
  `data[pad_digit:]` slices from the front; returns None so unpad slices
  by None; outer except still swallows; block size 0/256 not rejected in
  pad. Warmup: 10 failures.

## 2026-10-26 — seventh exchange

- **Test run (agent-run):** warmup 7 failures. Student's `pad_checker`
  now rejects `..00`, `..11`, `..01 02` and accepts `..02 02` (correct).
  Remaining: broad excepts in pad/unpad turn ValueError into None; pad
  does not reject block size 0/256; `data is None` vs empty; and
  `pad_digit in data` is membership, not range — agent demonstrated the
  counterexample 0x14×32 with block 16 being accepted (test written and
  run by agent).
- **Fingerprint (student draft) reviewed, not rewritten:** returns None
  because `str.encode` is applied to bytes / to the lookup function
  (log). Issues listed: lookup not called; private key used where public
  needed; label must be bytes; lowercase output; swallow.
- Handshake: no new code. Agent asked for the state-design and HELLO
  description (articulate-first) before any handshake code.

## 2026-10-26 — eighth exchange

- Student removed the broad excepts from pkcs7_pad/pkcs7_unpad. Agent
  renamed decorator uses to `@logged` in padding.py and protocol.py
  (glue, mechanical). Explained that a2.log records only ERROR level, so
  only raised exceptions appear.
- **Test run (agent-run):** warmup 1 failure + 2 errors. Left: pad does
  not call the block-size check (0 -> TypeError via helper except, 256
  accepted); unpad(b"") -> IndexError (`is None` check); out-of-range pad
  byte still accepted (no range check). Pointed out that the shared
  checker's empty/alignment rules are unpad-only.

## 2026-10-26 — ninth exchange (discussion only, no changes)

- Student asked whether `@logged` still captures generic exceptions.
  Agent explained log-then-re-raise vs swallow, where spec-specific
  catches belong (receive: DecodeError, PeerKeyUnavailable), and the
  duplicate-log-per-frame side effect. Concept explanation only.

## 2026-10-26 — tenth exchange

- **Test run (agent-run):** padding.py now fails on *import* (module-level
  test lines call pad(b"") and the new `block_checker` measures
  `len(data)` instead of the block_size argument). Warmup: 2 errors.
  Range check still absent in `pad_checker`; `null_checker` still `is None`.
- **Fingerprint (student draft):** structure correct (label bytes +
  key, SHA-256, [:10], hex with spaces). Self branch calls undefined
  `signature_key_gen`; result string is discarded and "" returned; no
  `.upper()`. Bob vector returned "". PeerKeyUnavailable propagates
  (correct). Review only; no code written by agent.

## 2026-10-26 — eleventh exchange

- Student: fixed block_checker signature, null check length, moved test
  lines under __main__, added @logged to Client methods, fixed fingerprint
  self branch to public_bytes. Agent fixed one import path typo
  (`starter.jmessage_support` -> `jmessage_support`) as glue.
- **Test run (agent-run):** warmup 3 errors. pad(b"") regressed to
  "Empty input" (null check now reached from pad). unpad(b"A", 0) ->
  ZeroDivisionError (modulo before block-size check). New range check
  uses data.count(p) not p; agent wrote and ran counterexample 0x01×32
  (valid padding, falsely rejected). Fingerprint: still returns "";
  no .upper(). Review only; no padding/fingerprint code written by agent.

## 2026-10-26 — twelfth exchange

- **Test run (agent-run):** `run_checks.py warmup` PASSES (2/2). Full
  probe: all valid cases unpad correctly incl. 0x01×32, sizes 1 and 255;
  all invalid cases raise ValueError. Fingerprint matches both Appendix A
  vectors (self F1 26..., bob B4 35...) and PeerKeyUnavailable propagates.
- Padding (Part 0) and fingerprint: designed, written and revised by the
  student. Agent contributions: symptom reports, counterexamples run,
  decorator refactor (glue), one import-path fix (glue). Agent never wrote
  padding or fingerprint code.
- Remaining nit noted: stray print() in fingerprint.
- Understanding check pending: "why is padding always added" (needed for
  design.md anyway). Handshake Q/A issued (state design + HELLO rule).

## 2026-10-26 — thirteenth exchange (handshake articulate-first, round 1)

- Student deferred the record-layer (MtE vs AEAD) question; recorded as
  deferred, not answered.
- Handshake Q/A answers: Q1 (state container) wrong — described
  messages.py/runtime instead of the Client's own per-sid structure.
  Q2 (pending-reply fields) mostly right: peer key, sid, ephemeral
  private key, HELLO bytes; missing peer name, role, start time, retry
  flag, (JM2) ML-KEM dk; secrets not marked; two terminology slips (sid
  called fingerprint; DH vs signature). Q3 (per-peer bookkeeping) wrong —
  described the server. Q4 (HELLO rule) incomplete: no library calls,
  suite lists, ek_I, stored bytes, or event. Q5 correct.
- Agent response: concept explanation with worked example (two
  simultaneous sids with one peer), recognition checks / fill-in table
  for Q1, Q3, Q4. No handshake code written yet.

## 2026-10-26 — fourteenth exchange (start_handshake implemented)

- Student's round-2 answers: Q1 (b) correct; unknown-sid REPLY question
  answered with the DATA path instead (gap). Q3.1 correct; Q3.2/Q3.3
  wrong values (peer->"local user", peer->"me"). Q4: suite order given
  as [JM1, JM2] (wrong order); ek_I given as os.urandom (wrong: it is the
  ML-KEM public key); sid source not named; event keys not named; reason
  for storing HELLO bytes correct.
- **Review-critical, implementation written by agent** after the
  articulate-first exchange: `Session` dataclass, `__init__` state
  (sessions/retired/queued/latest), `start_handshake`. Implemented the
  student's design (option b, dict keyed by sid; fields from Q2) and
  corrected the gaps above. Rules added that the student's description
  did not mention, listed to the student: sid redraw on collision with
  in-use/retired sid (§6.4 step 1); suite order [JM2, JM1] (§6.1); ek_I
  = ML-KEM encapsulation key, 1184 B, empty when JM1-only (§3, §6.3);
  send event dict keys; `offered` tuple retained for §6.5 step 1;
  started/retry_used fields. Comprehension questions added as comments.
- **Test written + run (agent):** in-memory Network harness; JM1-only
  HELLO = 54 B matching A.1 layout, default HELLO = 1240 B, state
  pending-reply, stored bytes == sent bytes; unknown peer -> error event,
  nothing sent, no state.
- Quiz pending (deadline-mode rule): see questions in reply.

## 2026-10-26 — fifteenth exchange (quiz after start_handshake)

- Quiz 1 (two start_handshake calls): student said 1 entry, merged.
  Wrong; agent ran it: 2 entries, 2 HELLOs, different sid/X_I, same
  peer. Explained that start_handshake is explicitly "fresh even if
  another exists" (handout §3) and the one-pending rule lives in
  send_text. Quiz 2: Encaps(ek_I) by Bob correct; Alice's Decaps(dk_I,
  ct) not stated; agent completed it. Quiz 3: correct.
- Q6–Q8 (HELLO processing, TH_R, dh) still unanswered; re-issued.

## 2026-10-26 — sixteenth exchange (responder Q/A round 1)

- Q6 (student): steps 1, 3 and "every REJECT retires sid" correct; step
  2 picks suite[0] (initiator's first) instead of responder preference
  order (gap); step 4 "retire + stop" right but "keypair per suite"
  wrong; step 5 ordering stores pending-finish before the crypto check.
  Agent corrected in prose. Q7 (TH_R / signature) and Q8 (dh) left
  blank — review-critical row missing; agent issued fill-in-the-blank
  recognition checks instead of implementing. No code written.
