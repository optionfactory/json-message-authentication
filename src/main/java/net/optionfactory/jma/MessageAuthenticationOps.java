package net.optionfactory.jma;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.function.Supplier;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import net.optionfactory.jma.stores.ConsumedTokenStore;

/// Authenticates and optionally encrypts self-contained JSON message tokens,
/// with optional single-use (replay-protected) semantics. Tokens have the form
/// `nonce.createdAt.payload.hmac` (dot-separated, url-safe base64 parts).
///
/// Two modes: [ #authenticate ]/[ #verifyAndDecode ] provide **integrity only**
/// (the payload is embedded in clear); [ #encryptThenAuthenticate ]/
/// [ #authenticateThenDecrypt ] also AES-encrypt the payload.
///
/// Decoders return a [SingleUse] wrapping the payload and a [SingleUse#recycle]
/// action that re-enables one more decode when the consuming operation failed.
/// The `attempts` argument bounds total decodes: `0` disables single-use, `1` is
/// strict (one decode, no recycle), `N` allows up to `N`.
public class MessageAuthenticationOps {

    private final Base64.Encoder b64enc = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder b64dec = Base64.getUrlDecoder();
    private final ConsumedTokenStore consumedTokenStore;
    private final SecretKeySpec aesKey;
    private final SecretKeySpec hmacKey;
    private final SecureRandom random;
    private final Supplier<Long> clock;
    private final int ivLength = 16;
    private final int saltLength = 12;

    public MessageAuthenticationOps(ConsumedTokenStore consumedTokenStore, SecretKeySpec aesKey, SecretKeySpec hmacKey, SecureRandom random, Supplier<Long> clock) {
        this.consumedTokenStore = consumedTokenStore;
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
        this.random = random;
        this.clock = clock;
    }

    /// Builds an ops with raw keys.
    ///
    /// @param consumedTokenStore tracks consumed tokens for replay protection.
    /// @param aesKey             32-byte AES key.
    /// @param hmacKey            64-byte HMAC-SHA256 key.
    /// @param random             source of nonces/IVs.
    /// @param clock              millisecond clock used for token timestamps/expiry.
    public static MessageAuthenticationOps create(ConsumedTokenStore consumedTokenStore, byte[] aesKey, byte[] hmacKey, SecureRandom random, Supplier<Long> clock) {
        if (aesKey.length != 32) {
            throw new MessageAuthenticationError("aesKey must be 32B long");
        }
        if (hmacKey.length != 64) {
            throw new MessageAuthenticationError("hmacKey is not 64B long");
        }
        return new MessageAuthenticationOps(
                consumedTokenStore,
                new SecretKeySpec(aesKey, "AES"),
                new SecretKeySpec(hmacKey, "HmacSHA256"),
                random,
                clock
        );
    }

    /// Builds an ops with string-encoded keys (see [KeyEncoding]).
    public static MessageAuthenticationOps create(ConsumedTokenStore consumedTokenStore, String encodedAesKey, String encodedHmacKey, SecureRandom random, Supplier<Long> clock, KeyEncoding keyEncoding) {
        final var aesKey = keyEncoding.decode(encodedAesKey);
        final var hmacKey = keyEncoding.decode(encodedHmacKey);
        return MessageAuthenticationOps.create(consumedTokenStore, aesKey, hmacKey, random, clock);
    }

    private byte[] randomBytes(int len) {
        final byte[] iv = new byte[len];
        random.nextBytes(iv);
        return iv;
    }

    private Mac initHmacSha256() {
        try {
            final var mac = Mac.getInstance("HmacSHA256");
            mac.init(hmacKey);
            return mac;
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }
    }

    private Cipher initAesCbcPkcs7(byte[] iv, int mode) {
        try {
            final var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(mode, aesKey, new IvParameterSpec(iv));
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }
    }

    /// Produces an authenticated (integrity-only) token. The payload is embedded
    /// in clear; use [ #encryptThenAuthenticate ] when confidentiality is needed.
    public String encryptThenAuthenticate(byte[] clearText) {
        final var iv = randomBytes(ivLength);
        final var createdAt = clock.get();

        try {
            final var cipherText = initAesCbcPkcs7(iv, Cipher.ENCRYPT_MODE).doFinal(clearText);

            final var mac = initHmacSha256();
            mac.update(ByteBuffer.allocate(8).putLong(createdAt).array());
            mac.update(iv);
            final var computedHmac = mac.doFinal(cipherText);

            return String.format("%s.%s.%s.%s",
                    b64enc.encodeToString(iv),
                    createdAt,
                    b64enc.encodeToString(cipherText),
                    b64enc.encodeToString(computedHmac)
            );
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }
    }

    /// Verifies the HMAC and validity window, then decrypts an
    /// [ #encryptThenAuthenticate ] token. See [ #verifyAndDecode ] for the
    /// `attempts` / [SingleUse] contract.
    public SingleUse<byte[]> authenticateThenDecrypt(String value, Duration validity, int attempts) {
        MessageAuthenticationError.enforce(validity != null && !validity.isZero() && !validity.isNegative(), "invalid validity duration");
        MessageAuthenticationError.enforce(attempts >= 0, "attempts must be >= 0");
        final long validityMs = validity.toMillis();
        final var split = value.split("\\.");
        MessageAuthenticationError.enforce(split.length == 4, "invalid parts");

        final byte[] iv;
        final long createdAt;
        final byte[] cipherText;
        final byte[] receivedHmac;

        try {
            iv = b64dec.decode(split[0]);
            createdAt = Long.parseLong(split[1]);
            cipherText = b64dec.decode(split[2]);
            receivedHmac = b64dec.decode(split[3]);
        } catch (IllegalArgumentException ex) {
            throw new MessageAuthenticationError("malformed token encoding");
        }

        final var now = clock.get();
        MessageAuthenticationError.enforce(iv.length == ivLength, "invalid iv");
        final var expiresAt = createdAt + validityMs;
        MessageAuthenticationError.enforce(expiresAt > now, "expired");

        final var mac = initHmacSha256();
        mac.update(ByteBuffer.allocate(8).putLong(createdAt).array());
        mac.update(iv);
        final var computedMessageHmac = mac.doFinal(cipherText);

        MessageAuthenticationError.enforce(MessageDigest.isEqual(computedMessageHmac, receivedHmac), "tampering");

        final byte[] clearText;
        try {
            clearText = initAesCbcPkcs7(iv, Cipher.DECRYPT_MODE).doFinal(cipherText);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }

        if (attempts == 0) {
            return new SingleUse<>(clearText, () -> {});
        }
        final var messageId = split[3];
        MessageAuthenticationError.enforce(this.consumedTokenStore.consume(messageId, expiresAt), "message already used");
        return new SingleUse<>(clearText, () -> MessageAuthenticationError.enforce(consumedTokenStore.recycle(messageId, attempts), "no attempts left"));
    }

    /// Produces an authenticated (integrity-only) token. The payload is embedded
    /// in clear; use [ #encryptThenAuthenticate ] when confidentiality is needed.
    public String authenticate(byte[] clearText) {

        final var createdAt = clock.get();
        final var salt = randomBytes(saltLength);
        final var mac = initHmacSha256();
        mac.update(ByteBuffer.allocate(8).putLong(createdAt).array());
        mac.update(salt);
        final var computedHmacValue = mac.doFinal(clearText);
        return String.format("%s.%s.%s.%s",
                b64enc.encodeToString(salt),
                createdAt,
                b64enc.encodeToString(clearText),
                b64enc.encodeToString(computedHmacValue)
        );
    }

    /// Verifies the HMAC and validity window of an authenticated token, optionally
    /// consuming it for replay protection, and returns the decoded payload.
    ///
    /// @param authenticated the token produced by [ #authenticate ].
    /// @param validity      how long the token remains valid (must be positive).
    /// @param attempts      single-use policy: `0` disables it (no consumption,
    ///                      [SingleUse#recycle] is a no-op); `1` enables strict
    ///                      single-use (one decode, `recycle` throws); `N` allows
    ///                      up to `N` decodes, with `recycle` re-enabling one more.
    /// @return the payload and a [SingleUse#recycle] action.
    public SingleUse<byte[]> verifyAndDecode(String authenticated, Duration validity, int attempts) {
        MessageAuthenticationError.enforce(validity != null && !validity.isZero() && !validity.isNegative(), "invalid validity duration");
        MessageAuthenticationError.enforce(attempts >= 0, "attempts must be >= 0");
        final long validityMs = validity.toMillis();
        final var split = authenticated.split("\\.");
        MessageAuthenticationError.enforce(split.length == 4, "invalid parts");

        final byte[] salt;
        final long createdAt;
        final byte[] hmacValue;
        final byte[] clearText;

        try {
            salt = b64dec.decode(split[0]);
            createdAt = Long.parseLong(split[1]);
            clearText = b64dec.decode(split[2]);
            hmacValue = b64dec.decode(split[3]);
        } catch (IllegalArgumentException ex) {
            throw new MessageAuthenticationError("malformed token encoding");
        }

        final var now = clock.get();
        MessageAuthenticationError.enforce(salt.length == saltLength, "invalid salt");
        final var expiresAt = createdAt + validityMs;
        MessageAuthenticationError.enforce(expiresAt > now, "expired");

        final var sha256 = initHmacSha256();
        sha256.update(ByteBuffer.allocate(8).putLong(createdAt).array());
        sha256.update(salt);
        final var computedHmacValue = sha256.doFinal(clearText);

        MessageAuthenticationError.enforce(MessageDigest.isEqual(computedHmacValue, hmacValue), "tampering");

        if (attempts == 0) {
            return new SingleUse<>(clearText, () -> {});
        }
        final var messageId = split[3];
        MessageAuthenticationError.enforce(this.consumedTokenStore.consume(messageId, expiresAt), "message already used");
        return new SingleUse<>(clearText, () -> MessageAuthenticationError.enforce(consumedTokenStore.recycle(messageId, attempts), "no attempts left"));
    }

    public enum KeyEncoding {
        URL_SAFE_BASE_64,
        BASE_64,
        HEX;

        public byte[] decode(String source) {
            switch (this) {
                case URL_SAFE_BASE_64:
                    return Base64.getUrlDecoder().decode(source);
                case BASE_64:
                    return Base64.getDecoder().decode(source);
                case HEX:
                    if (source.length() % 2 == 1) {
                        throw new IllegalArgumentException(String.format("Hex encoded value has an odd length: %s", source));
                    }
                    final byte[] bytes = new byte[source.length() / 2];
                    for (int i = 0; i != source.length() / 2; ++i) {
                        final char c1 = source.charAt(i * 2 + 0);
                        final char c2 = source.charAt(i * 2 + 1);
                        final int d1 = Character.digit(c1, 16);
                        final int d2 = Character.digit(c2, 16);
                        if (d1 == -1 || d2 == -1) {
                            throw new IllegalArgumentException(String.format("Invalid hex character found in string: '%s' or '%s'", c1, c2));
                        }
                        bytes[i] = (byte) ((d1 << 4) + d2);
                    }
                    return bytes;
                default:
                    throw new IllegalArgumentException(String.format("Unkown encoding: %s", this));
            }
        }
    }

}
