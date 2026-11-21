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
