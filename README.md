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
nonce.createdAt.payload.hmac
```

`createdAt` is a millisecond timestamp; `hmac` is HMAC-SHA256 over
`createdAt || nonce || payload`. Two modes:

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

Serialization produces the token; deserialization verifies the HMAC and validity
window, then decodes. `attempts` controls single-use semantics (see below).

### Standalone (no Jackson)

```java
var ops = MessageAuthenticationOps.create(store, aesKey, hmacKey, random, clock, KeyEncoding.BASE_64);
String token = ops.encryptThenAuthenticate(payload);
SingleUse<byte[]> su = ops.authenticateThenDecrypt(token, Duration.ofHours(1), 1);
byte[] payload = su.value();
```

## Single-use / replay protection

`attempts` bounds how many times a token can be decoded:

- `0` (default) — single-use **disabled**. The token is freely decodable until it
  expires. Matches pre-3.0 behavior.
- `1` — **strict** single-use: one decode, no retry.
- `N` — up to `N` decodes.

Decoding consumes one attempt and blocks the token. If the operation that used the
decoded value fails, call `SingleUse.recycle()` to re-enable one more decode:

```java
SingleUse<Foo> su = ops.authenticateThenDecrypt(token, validity, 3);
try {
    doSomething(su.value());
} catch (Exception e) {
    su.recycle();   // give one attempt back so the caller can retry
    throw e;
}
// success → do nothing; the token stays blocked
```

### Aggregated retry for a bean (`SingleUse<Bean>`)

A bean may carry several `@MessageAuthentication` fields (including nested ones).
Deserialize as `SingleUse<Bean>` to obtain **one** handle whose `recycle()`
re-enables *all* of the bean's tokens. If deserialization fails partway, the
already-consumed tokens are recycled automatically (rolled back) before the error
propagates.

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
consumption is rolled back and the request fails normally — no token is burned.

If the bean contains a strict (`attempts = 1`) field, `recycle()` throws — such a
bean is not retryable.

Plain `mapper.readValue(json, MyBean.class)` (without `SingleUse`) still works;
it consumes strictly and discards the handle, so there is no retry path.

## Threat model

**What this protects against**

- **Tampering** — any change to a token's parts invalidates the HMAC
  (compared with `MessageDigest.isEqual`, constant-time).
- **Replay** — when `attempts >= 1`, a decoded token is blocked from reuse.
- **Disclosure of the payload** — in `AUTHENTICATED_ENCRYPTED` mode only.

**Assumptions**

- The AES key (32 bytes) and HMAC key (64 bytes) are secret and held server-side.
- A reasonably correct monotonic clock.

**What this does not do**

- It does not replace TLS, authenticate a *user*, or carry identity/claims (the
  token holds only a timestamp).
- It does not provide key management or rotation.
- It does not protect against an attacker who has obtained the keys.

**Single-use caveats**

- `recycle()` deliberately re-opens a decode slot, which is a brief replay window
  (bounded by `attempts`); use the smallest budget that meets your retry needs and
  keep `validity` short.
- The bundled `InMemoryConsumedTokenStore` is **per-instance** — its state is not
  shared across processes. For a multi-instance deployment, implement
  `ConsumedTokenStore` against a shared store (e.g. Redis) so consumption is
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
