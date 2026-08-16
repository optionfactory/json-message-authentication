package net.optionfactory.jma;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicLong;
import javax.crypto.spec.SecretKeySpec;
import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import net.optionfactory.jma.stores.InMemoryConsumedTokenStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

public class MessageAuthenticationOpsTest {

    private static final String AES = "hCVxn9jkw5WKeS2tjlO5bMmD4eHwm+P8daHUHesimnA=";
    private static final String HMAC = "CRejIvb47whaMpIBNVAxym8Mbe33mbX0UbXaUJ2pKEaKiF8uRTlO5QzQTAPEhMKzZzuuGhJEaWcYGjti6Y4YZA==";

    private AtomicLong now;
    private MessageAuthenticationOps maops;
    private JsonMapper mapper;

    public record NestedObject(String value1, String value2, String value3) {
    }

    @BeforeEach
    public void setup() {
        this.now = new AtomicLong(1_000_000L);
        this.maops = MessageAuthenticationOps.create(
                new InMemoryConsumedTokenStore(now::get),
                AES, HMAC, new SecureRandom(), now::get, KeyEncoding.BASE_64);
        this.mapper = new JsonMapper();
    }

    @Test
    public void authenticatedRoundTrip() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.authenticate(payload, Duration.ofSeconds(60));
        Assertions.assertArrayEquals(payload, maops.verifyAndDecode(token, 1).value());
    }

    @Test
    public void authenticatedObjectRoundTrip() throws Exception {
        final var src = new NestedObject("11111", "22222", "33333");
        final var json = mapper.writeValueAsString(src);
        final var token = maops.authenticate(json.getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        final var clear = maops.verifyAndDecode(token, 1).value();
        Assertions.assertEquals(src, mapper.readValue(clear, NestedObject.class));
    }

    @Test
    public void encryptedRoundTrip() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.encryptThenAuthenticate(payload, Duration.ofSeconds(60));
        Assertions.assertArrayEquals(payload, maops.authenticateThenDecrypt(token, 1).value());
    }

    @Test
    public void encryptedObjectRoundTrip() throws Exception {
        final var src = new NestedObject("11111", "22222", "33333");
        final var json = mapper.writeValueAsString(src);
        final var token = maops.encryptThenAuthenticate(json.getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        final var clear = maops.authenticateThenDecrypt(token, 1).value();
        Assertions.assertEquals(src, mapper.readValue(clear, NestedObject.class));
    }

    @Test
    public void encryptedTokenDoesNotExposeClearText() {
        final var token = maops.encryptThenAuthenticate("secret".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertFalse(token.contains("secret"));
    }

    @Test
    public void authenticatedReplayThrowsTokenAlreadyUsed() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        maops.verifyAndDecode(token, 1);
        Assertions.assertThrows(TokenAlreadyUsed.class, () -> maops.verifyAndDecode(token, 1));
    }

    @Test
    public void encryptedReplayThrowsTokenAlreadyUsed() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        maops.authenticateThenDecrypt(token, 1);
        Assertions.assertThrows(TokenAlreadyUsed.class, () -> maops.authenticateThenDecrypt(token, 1));
    }

    @Test
    public void encryptedTokenIsRejectedByAuthenticatedDecoder() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertThrows(TokenMalformed.class, () -> maops.verifyAndDecode(token, 1));
    }

    @Test
    public void authenticatedTokenIsRejectedByEncryptedDecoder() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertThrows(TokenMalformed.class, () -> maops.authenticateThenDecrypt(token, 1));
    }

    @Test
    public void authenticatedTamperingSaltThrowsTokenMalformed() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertThrows(TokenMalformed.class, () -> maops.verifyAndDecode(tamper(token, 0), 1));
    }

    @Test
    public void authenticatedTamperingWindowThrowsTokenMalformed() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertThrows(TokenMalformed.class, () -> maops.verifyAndDecode(tamper(token, 1), 1));
    }

    @Test
    public void authenticatedTamperingPayloadThrowsTokenMalformed() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertThrows(TokenMalformed.class, () -> maops.verifyAndDecode(tamper(token, 2), 1));
    }

    @Test
    public void authenticatedTamperingHmacThrowsTokenMalformed() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertThrows(TokenMalformed.class, () -> maops.verifyAndDecode(tamper(token, 3), 1));
    }

    @Test
    public void encryptedTamperingIvThrowsTokenMalformed() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertThrows(TokenMalformed.class, () -> maops.authenticateThenDecrypt(tamper(token, 0), 1));
    }

    @Test
    public void encryptedTamperingWindowThrowsTokenMalformed() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertThrows(TokenMalformed.class, () -> maops.authenticateThenDecrypt(tamper(token, 1), 1));
    }

    @Test
    public void encryptedTamperingCipherTextThrowsTokenMalformed() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertThrows(TokenMalformed.class, () -> maops.authenticateThenDecrypt(tamper(token, 2), 1));
    }

    @Test
    public void encryptedTamperingHmacThrowsTokenMalformed() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertThrows(TokenMalformed.class, () -> maops.authenticateThenDecrypt(tamper(token, 3), 1));
    }

    @Test
    public void authenticatedExpiredThrowsTokenExpired() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        now.addAndGet(120_000L);
        Assertions.assertThrows(TokenExpired.class, () -> maops.verifyAndDecode(token, 1));
    }

    @Test
    public void encryptedExpiredThrowsTokenExpired() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        now.addAndGet(120_000L);
        Assertions.assertThrows(TokenExpired.class, () -> maops.authenticateThenDecrypt(token, 1));
    }

    @Test
    public void wrongNumberOfPartsThrowsTokenMalformed() {
        Assertions.assertThrows(TokenMalformed.class, () -> maops.verifyAndDecode("a.b.c", 1));
    }

    @Test
    public void nullAuthenticatedTokenThrowsTokenMalformed() {
        Assertions.assertThrows(TokenMalformed.class, () -> maops.verifyAndDecode(null, 1));
    }

    @Test
    public void nullEncryptedTokenThrowsTokenMalformed() {
        Assertions.assertThrows(TokenMalformed.class, () -> maops.authenticateThenDecrypt(null, 1));
    }

    @Test
    public void shortWindowThrowsTokenMalformed() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        final var parts = token.split("\\.");
        parts[1] = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[8]);
        Assertions.assertThrows(TokenMalformed.class, () -> maops.verifyAndDecode(String.join(".", parts), 1));
    }

    @Test
    public void paddedWindowEncodingThrowsTokenMalformed() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        final var parts = token.split("\\.");
        parts[1] = parts[1] + "==";
        Assertions.assertThrows(TokenMalformed.class, () -> maops.verifyAndDecode(String.join(".", parts), 1));
    }

    @Test
    public void encryptedShortWindowThrowsTokenMalformed() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        final var parts = token.split("\\.");
        parts[1] = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[8]);
        Assertions.assertThrows(TokenMalformed.class, () -> maops.authenticateThenDecrypt(String.join(".", parts), 1));
    }

    @Test
    public void nullValidityIsRejectedAsIllegalArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), null));
    }

    @Test
    public void zeroValidityIsRejectedAsIllegalArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ZERO));
    }

    @Test
    public void negativeValidityIsRejectedAsIllegalArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(-1)));
    }

    @Test
    public void negativeAttemptsIsRejectedAsIllegalArgument() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60));
        Assertions.assertThrows(IllegalArgumentException.class, () -> maops.verifyAndDecode(token, -1));
    }

    @Test
    public void encryptedNullValidityIsRejectedAsIllegalArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8), null));
    }

    @Test
    public void encryptedZeroValidityIsRejectedAsIllegalArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ZERO));
    }

    @Test
    public void encryptedNegativeValidityIsRejectedAsIllegalArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(-1)));
    }

    @Test
    public void encryptedNegativeAttemptsIsRejectedAsIllegalArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> maops.authenticateThenDecrypt("a.b.c.d", -1));
    }

    @Test
    public void encryptedWrongNumberOfPartsThrowsTokenMalformed() {
        Assertions.assertThrows(TokenMalformed.class, () -> maops.authenticateThenDecrypt("a.b.c", 1));
    }

    @Test
    public void createRejectsShortAesKeyAsIllegalArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> MessageAuthenticationOps.create(
                new InMemoryConsumedTokenStore(() -> 0L),
                new byte[16], new byte[64], new SecureRandom(), () -> 0L));
    }

    @Test
    public void createRejectsShortHmacKeyAsIllegalArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> MessageAuthenticationOps.create(
                new InMemoryConsumedTokenStore(() -> 0L),
                new byte[32], new byte[32], new SecureRandom(), () -> 0L));
    }

    @Test
    public void constructorRejectsWrongAesAlgorithmAsIllegalArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new MessageAuthenticationOps(
                new InMemoryConsumedTokenStore(() -> 0L),
                new SecretKeySpec(new byte[32], "AES/GCM/NoPadding"),
                new SecretKeySpec(new byte[64], "HmacSHA256"),
                new SecureRandom(), () -> 0L));
    }

    @Test
    public void constructorRejectsWrongHmacAlgorithmAsIllegalArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new MessageAuthenticationOps(
                new InMemoryConsumedTokenStore(() -> 0L),
                new SecretKeySpec(new byte[32], "AES"),
                new SecretKeySpec(new byte[64], "HmacSHA384"),
                new SecureRandom(), () -> 0L));
    }

    private static String tamper(String token, int part) {
        final var parts = token.split("\\.");
        final var p = new StringBuilder(parts[part]);
        final char c = p.charAt(0);
        p.setCharAt(0, c == 'A' ? 'B' : 'A');
        parts[part] = p.toString();
        return String.join(".", parts);
    }
}
