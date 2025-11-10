# nora = nonce ratchet
Generating deterministic nonces.

Program for generating deterministic nonces, per day,
so that Alice and Bob do not have to send them to each
other. It doesn't matter which time zones they are
currently in.

This program is intended for the use of my [ChaCha20](https://github.com/Ch1ffr3punk/chacha20) program,
which requires 12 bytes hex nonces, in addition to the use of a 32 bytes hex key.

