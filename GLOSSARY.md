# Blink

Blink is a self-hosted, end-to-end encrypted secret-sharing app: a sender creates a one-time link, a recipient reveals it once, and the server never sees the plaintext or the complete encryption key.

## Language

### Cryptographic model

**K**:
The AES-256-GCM key that encrypts a secret. Never stored or transmitted whole; reconstructed only in the recipient's browser, from `K1` and `K2`, at reveal.
_Avoid_: encryption key (as a standalone term), master key

**K1**:
Half of `K`. Stays in the URL fragment and never reaches the server - only its hash does.
_Avoid_: client key, user key

**K2**:
Half of `K`. Sent to the server at creation, masked at rest with `K3`, and released to the recipient's browser only after the `K1` hash check passes.
_Avoid_: server key (ambiguous with `K3`/`K4`, which never leave the server at all)

**K3**:
A permanent, server-only secret (`SECRET_KEY`) that masks `K2` at rest via HMAC. Required in production.
_Avoid_: HMAC key alone (doesn't say what it protects)

**K4**:
A permanent, server-only secret (`CIPHER_KEY`) that re-encrypts stored ciphertext at rest. Required in production.
_Avoid_: encryption-at-rest key

**K1 hash**:
`SHA-256(K1)`, sent by the browser at both creation and reveal in place of `K1` itself, letting the server verify key possession without ever seeing `K1`.
_Avoid_: key hash, verification hash

### Secret lifecycle

**Secret**:
The plaintext content a sender wants to share (a password, a note, a file). Exists as plaintext only in the sender's and recipient's browsers, never on the server.
_Avoid_: message, data, content

**Ciphertext**:
A secret after AES-256-GCM encryption, as stored on the server and carried in the link's API calls. Never decryptable without both `K1` and `K2`.
_Avoid_: encrypted data, payload

**Link**:
The full URL given to the sender to share: the secret's server-side id plus `K1` in the fragment. Combines everything a recipient needs except what the server itself holds.
_Avoid_: URL (loses the K1-in-fragment structure), share link

**View**:
One unit of permitted access to a secret. A secret is created with a fixed number of views (one, by default); each reveal consumes one.
_Avoid_: open, access, read

**Reveal**:
The act of a recipient's browser decrypting and displaying a secret - which also consumes one view and, server-side, releases `K2` and decrements or deletes the secret. Distinct from `View`: a view is the unit being spent, a reveal is the act of spending it.
_Avoid_: open, view (as a verb), unlock

**View-once**:
The default behavior: a secret created with exactly one view, deleted immediately after its single reveal.
_Avoid_: single-use, one-time

**Multi-view** (Pro):
A secret created with more than one view. Decrements per reveal; deleted after the last one.
_Avoid_: multiple reads

**Expiry**:
The time window (1, 6, 24, or 48 hours - 7 days for Pro) after which an unrevealed secret is purged regardless of views remaining.
_Avoid_: TTL, timeout

**Graceful-restart snapshot**:
An on-disk copy of in-memory secrets and rate-limiter state, written only during a clean shutdown (e.g. a deploy) and reloaded on the next startup, so a restart doesn't lose unrevealed secrets. A hard crash or `SIGKILL` still loses everything in memory - this only covers a graceful stop.
_Avoid_: backup, persistence layer

### Reveal gates

**OTP** (one-time code):
A 6-digit code emailed to a recipient, required before reveal when a sender locks a link to a specific recipient's email. Five wrong attempts destroys the secret.
_Avoid_: verification code, 2FA code

**Passphrase** (Pro):
An additional secret string, chosen by the sender, that a recipient must supply before reveal - independent of the link itself.
_Avoid_: password (reserved for the password-generator feature, a different concept)

### People

**Sender**:
The person who creates a secret and shares the resulting link.
_Avoid_: creator, user

**Recipient**:
The person who opens a link and reveals the secret.
_Avoid_: viewer, reader, user

### Pro & licensing

**Pro**:
The paid tier: unlocks multi-view, passphrase protection, 7-day expiry, and view notifications.
_Avoid_: premium, paid plan

**Owner account**:
An email listed in `OWNER_EMAILS`, always treated as Pro with no license key or purchase needed - for the deployment's own operator(s).
_Avoid_: admin, superuser

**License**:
A Lemon Squeezy-issued key a Pro account activates once to unlock Pro features, bound to exactly one signed-in account (Activation Limit = 1).
_Avoid_: subscription, token

### Browser extension

**Bubble**:
The floating button the extension's content script shows next to a text selection on any page, offering a one-click "Send via Blink."
_Avoid_: widget, popup (reserved for the toolbar popup - a different UI surface)
