# json-message-authentication

A small Jackson module (plus a standalone facade) for HMAC-authenticated,
optionally AES-encrypted JSON message tokens, with optional **single-use**
(replay-protected) decoding.

It is intended for self-contained action tokens — password-reset / email-verify
links, invitations, one-shot confirmations — and for authenticating individual
fields in a JSON payload. It is **not** a session/JWT library, a user-authentication
library, or a key-management system.

## How it works

A token is a string of four dot-separated, url-safe base64 parts:

```
nonce.window.payload.hmac
```

`window` packs the millisecond creation timestamp and the validity (ttl) fixed
at issuance; `hmac` is HMAC-SHA256 over `tag || nonce || window || payload` —
a one-byte mode tag, then the parts in the order they appear on the wire. The
tag domain-separates the two modes, so a token minted in one mode can never
authenticate in the other. Because
the validity is embedded in the token and covered by the HMAC, it is committed
at issuance: verifiers derive the expiry from the token itself and cannot
reinterpret or extend it. Two modes:

- **`AUTHENTICATED`** — integrity only. The payload is embedded in clear text.
- **`AUTHENTICATED_ENCRYPTED`** — the payload is AES-256-CBC encrypted and the
  ciphertext is MAC'd (encrypt-then-MAC), so it is also confidential.

### As a Jackson module

Annotate a field or type:

```java
public record ResetRequest(
    String userId,
    @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED, validity = 1, unit = ChronoUnit.HOURS, attempts = 1)
    String token
) {}
```

Serialization produces the token (embedding the annotation's `validity`);
deserialization verifies the HMAC and validity window, then decodes. `attempts`
controls single-use semantics (see below).

### As a meta-annotation (bundle)

`@MessageAuthentication` may be placed on your own annotation to fix a set of
defaults, then the bundle used in place of the full declaration:

```java
@MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED, validity = 1, unit = ChronoUnit.HOURS, attempts = 1)
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.PARAMETER})
public @interface ResetToken {}

public record ResetRequest(String userId, @ResetToken String token) {}
```

The bundle annotation must be `@Retention(RUNTIME)`, and its `@Target` should
mirror `@MessageAuthentication`'s (`FIELD`, `PARAMETER`; add `TYPE` for
type-level bundles). **`PARAMETER` is required** for the bundle to work on
record components — records deserialize through the constructor parameter, so an
annotation declared `@Target(FIELD)` only would be invisible to deserialization.
A direct `@MessageAuthentication` takes precedence over a bundle annotation.

### Standalone (no Jackson)

```java
var ops = MessageAuthenticationOps.create(store, aesKey, hmacKey, random, clock, KeyEncoding.BASE_64);
String token = ops.encryptThenAuthenticate(payload, Duration.ofHours(1));
SingleUse<byte[]> su = ops.authenticateThenDecrypt(token, 1);
byte[] payload = su.value();
```

## Single-use / replay protection

`attempts` bounds how many times a token can be decoded:

- `0` (default) — single-use **disabled**. The token is freely decodable until it
  expires. Matches pre-3.0 behavior.
- `1` — **strict** single-use: one decode, no retry.
- `N` — up to `N` decodes.

Decoding consumes one attempt and denylists the token. Two recovery actions
exist, for two different failures:

- `recycle()` — the guarded action **ran and failed**: the token is un-blocked
  for one more decode, but the attempt stays spent. Bounded by `attempts`
  (throws `TokenDepleted` when the budget is exhausted).
- `refund()` — an **upstream failure prevented the action from running at all**
  (e.g. the database was down, so nothing happened): the attempt is given back
  and the token returns to a virgin state — even a strict (`attempts = 1`)
  token. Use it only when the token-warded action certainly did not execute:
  refunding after a *successful* action re-opens the token with **no budget
  bound**.

```java
SingleUse<Foo> su = ops.authenticateThenDecrypt(token, 1);
try {
    doSomething(su.value());
} catch (ActionFailedException e) {
    su.recycle();   // action ran and failed: retry within the budget
    throw e;
} catch (UpstreamUnavailableException e) {
    su.refund();    // action never ran: give the attempt back
    throw e;
}
// success → do nothing; the token stays blocked
```

### Aggregated retry for a bean (`SingleUse<Bean>`)

A bean may carry several `@MessageAuthentication` fields (including nested ones).
Deserialize as `SingleUse<Bean>` to obtain **one** handle whose `recycle()` /
`refund()` applies to *all* of the bean's tokens. If deserialization fails
partway, the already-consumed tokens are **refunded** (rolled back as if never
consumed) before the error propagates — so even a strict (`attempts = 1`) field
is not burned by a malformed request.

```java
SingleUse<MyBean> su = mapper.readValue(json, new TypeReference<SingleUse<MyBean>>(){});
MyBean bean = su.value();
try { handle(bean); } catch (Exception e) { su.recycle(); throw e; }
```

#### With Spring (`@RequestBody`)

Register the module to Spring `JsonMapper`, then type the
parameter as `SingleUse<Bean>`:

```java
@Bean
Module messageAuthentication(MessageAuthenticationOps ops) {
    return new MessageAuthenticationModule(ops);
}

@RestController
static class ConfirmController {

    @PostMapping("/confirm")
    public void confirm(@RequestBody SingleUse<ConfirmRequest> body) {
        try {
            handle(body.value());
        } catch (Exception e) {
            body.recycle();   // retry the whole request on failure
            throw e;
        }
        // success → do nothing; every token in the bean stays blocked
    }
}
```

`body.value()` is the decoded bean; `body.recycle()` re-enables all of its tokens
at once. If deserialization itself fails (e.g. a replayed or expired token),
consumption is refunded (rolled back as if never consumed) and the request fails
normally — no token is burned, not even a strict one.

If the bean contains a strict (`attempts = 1`) field, `recycle()` throws — such a
bean is not retryable. `refund()` still works: it does not need retry budget.

Plain `mapper.readValue(json, MyBean.class)` (without `SingleUse`) still works;
it consumes strictly and discards the handle, so there is no retry path.

## Threat model

**What this protects against**

- **Tampering** — any change to a token's parts invalidates the HMAC
  (compared with `MessageDigest.isEqual`, constant-time).
- **Replay** — when `attempts >= 1`, a decoded token is blocked from reuse.
  The denylist entry lives until the token's own (issuance-committed) expiry,
  so a consumed token cannot outlive its denylist record.
- **Disclosure of the payload** — in `AUTHENTICATED_ENCRYPTED` mode only.

**Assumptions**

- The AES key (32 bytes) and HMAC key (64 bytes) are secret and held server-side.
- A reasonably correct monotonic clock.

**What this does not do**

- It does not replace TLS, authenticate a *user*, or carry identity/claims (the
  token holds only a creation timestamp and a validity).
- It does not provide key management or rotation.
- It does not protect against an attacker who has obtained the keys.

**Single-use caveats**

- `recycle()` deliberately re-opens a decode slot, which is a brief replay window
  (bounded by `attempts`); use the smallest budget that meets your retry needs and
  keep `validity` short.
- `attempts` bounds decodes **net of refunds**: the invariant is
  `decodes − refunds ≤ attempts`, not "at most `attempts` decodes, ever". When
  upstream failures interleave with retries, a token can legitimately be *seen*
  decoding more than `attempts` times in logs and metrics — each refund
  corresponds to a decode whose guarded action never ran. What stays bounded is
  the number of decodes whose action may have executed, and the token is blocked
  once an action succeeds. Don't alert on raw decode counts; alert on
  non-refunded consumption.
- `refund()` after a *successful* action re-opens the token with no budget bound —
  this is caller misuse, not an attacker-triggerable condition, but treat any
  refund call site as security-sensitive code.
- The bundled `InMemoryConsumedTokenStore` is **per-instance** — its state is not
  shared across processes. For a multi-instance deployment, implement
  `ConsumedTokenStore` against a shared store (e.g. Postgres) so consumption is
  coordinated.

**Crypto choices**

AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC), with a fresh random 128-bit IV per
token and a single long-lived key reused across tokens. This is deliberate: CBC
is tolerant of an IV collision (it only leaks equality of a plaintext prefix),
which makes it a good fit for a stateless, random-IV-per-token design.

AES-GCM is **not** a drop-in upgrade here. Its security fails *catastrophically*
on a single nonce reuse under the same key, and with random nonces NIST caps GCM
at roughly 2^32 encryptions per key before the collision risk becomes
unacceptable. Safe GCM use would require a durably-managed, never-repeating
counter nonce — a materially different design.

## Failure handling

Token failures throw a `MessageAuthenticationError` (a `RuntimeException`); catch
the base type to handle any failure, or a subtype for a specific category:

- `TokenExpired` — past the validity window
- `TokenMalformed` — HMAC mismatch or unparseable structure (tampered/corrupt)
- `TokenAlreadyUsed` — the token is already blocked (replay/duplicate)
- `TokenDepleted` — the retry budget is exhausted (recycle rejected)

Invalid arguments (e.g. a negative `attempts`) raise `IllegalArgumentException`
and environment/internal failures raise `IllegalStateException` — both are
deliberately outside the `MessageAuthenticationError` hierarchy, since they are
not token conditions.

```java
try {
    handle(su.value());
} catch (TokenExpired e) {
    // 410 — tell the client to get a fresh token
} catch (TokenAlreadyUsed | TokenDepleted e) {
    // 409 — already consumed / out of retries
} catch (MessageAuthenticationError e) {
    // 400 — tampered or malformed
}
```

## Limitations / non-goals

- No built-in distributed token store.
- No key rotation or management.

## Installation

```xml
<dependency>
  <groupId>net.optionfactory</groupId>
  <artifactId>json-message-authentication</artifactId>
</dependency>
```

Requires Java 21+ and Jackson 3.x (`tools.jackson.databind`).

## License

BSD-2-Clause. See [LICENSE](LICENSE).
