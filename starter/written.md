# Written explanation and repair analysis

1. What establishes the association between a username and an identity key? What does
a valid signature establish when that association is untrusted?

The Ed25519 key (long-term), it is uploaded to the server (the public-key) and is used to lookup
and contact other members of the messaging application. The fingerprint of the user 
(a shortened/salted version of the key) would ideally be verified with the user via another secure
channel to establish the user is (physicaly) who they claim to be. What the username and the idPk@server
do is cryptographically ensure message integrity via a longterm signature scheme they do not verify the
identity of the person but verify messages bind to a specific key; who is behind that key would need an 
additional form of verification.

2. Trace the initiator’s and responder’s inputs to the JM2 key schedule. Explain why
they agree and why the two traffic directions use different keys.

Initiator provides their dh elliptic curve secret and also an ML-KEM public key for hybrid key derivation.
Bob receives this and sends back their part of the Diffie hellman secret but also encapsulates the ML-KEM 
secret to establish the ephemeral AEAD keys needed for the session.

3. Which negotiation data does each signature cover? Explain why checking one hand-
shake transcript does not by itself establish the security of the application’s broader
negotiation policy.

We have HELLO, REPLY, AND FINISH. HELLO attempts to establish an initial connection with a peer and sends their
corresponding chosen suite as well as secrets for a reply-back. If we didn't attempt negotiating the suite
then messages would simply be dropped if  the other party could not use the corresponding AEAD scheme (or worse, raw plain-text communication).
Hence the REPLY is needed to resolve if the suite being propposed is accepted by the receiver (and if the receiver wants to communicate at all;
a non-recognized user could be dropped here). Finally the FINISH allows to communicate under the chosen suite (with shared secrets on each side)
but it also (cryptographically) ensures that no MITM impersonation took place (via the message signing and sharing the entire handshake-signed-messages themselves).

REJECT is used to communicate failure in message processing during the handshake either because of the suite or tampering but it DOES NOT cover
the message that was rejected (hence attacks such as the one we performed can occur). The signature didn't fail for the REJECT, it was just not covering
all fields it should have covered.

4. Explain the distinct receive outcomes for JM1 and JM2 and their security implications.

Evaluate a record-layer repair and describe the acceptance and rejection behavior it
should have.
JM1 is MAC then Encrypt (which when *wrongfully implemented* is prone to padding/length extension attacks) and
JM2 is an AEAD that avoids this and also provides PQC protection from the *quantum computers* for key exchange during the handshake.

5. Propose a negotiation-policy repair. State the property restored, its compatibility
cost, and a limitation it does not address.

So to fix this I would move from MAC-then-Encrypt to AES-GMC (not much cost anyway, since you are already doing AES/MAC)
and the AEAD should now protect from padding oracle attacks. And I would enforce some stricter counters (say on REJECT/Handshake messages) so that the other party can be aware of multiple packages being dropped (oracle/bot-like behavior). I would also attempt a more robust REJECT message
that includes the rejected message as well so the other party can verify the signature and notice tampering on their message.
Slight boost on the primitives, more robust implementation in terms of counter-handling and REJECT messages.

6. Does adding ML-KEM make this entire protocol post-quantum secure? Distinguish
key agreement from identity authentication, and explain what FINISH and RECEIPT
do and do not confirm.

There is the long-term identity authentication, the message encryption/decryption and the signature scheme. 
Only the key exchange during the handshake is PQC secure. All other primitives could still be broken and we end up with
a potentially insecure system.

Extra credit (up to 6 points): assistants at the endpoint
Suppose a JMessage client includes an AI assistant that reads incoming messages, summa-
rizes conversations, and can send replies on the user’s behalf. Its model runs either on the
user’s device or on a remote inference service inside a trusted execution environment (TEE)
whose code is publicly attested. Answer each question in two or three paragraphs. No code
is required, and you should not test any of this against real services or other students.
7. End-to-end encryption is usually described as protecting messages “from everyone ex-
cept the endpoints.” Where is the endpoint in this design? Use the lethal-trifecta
framing (access to private data, exposure to untrusted content, and a channel to send
data out) to explain why a message from an authenticated sender can still cause the
assistant to disclose another conversation. Which JMessage guarantees still hold, and
which ones stop mattering?

8. What does a TEE with remote attestation actually guarantee here, and to whom?
Compare the threat it addresses with the threat in question 7. Use a deployed design
as your example, such as Meta’s Private Processing for WhatsApp or Apple’s Private
Cloud Compute.

9. If many users run such assistants, explain at the level of system design how a single
message could spread from assistant to assistant, as in the Morris II study of self-
replicating prompts (Cohen, Bitton and Nassi, 2024). Evaluate two mitigations and
state what each one costs in usefulness. Examples: user confirmation before any
send, per-conversation context isolation, tracking where data came from, or plan-then-
execute designs such as CaMeL. Is any of these mitigations a cryptographic property?