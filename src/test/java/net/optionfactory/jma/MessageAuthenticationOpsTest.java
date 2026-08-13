package net.optionfactory.jma;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
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
        final var token = maops.authenticate(payload);
        Assertions.assertArrayEquals(payload, maops.verifyAndDecode(token, Duration.ofSeconds(60), 1).value());
    }

    @Test
    public void authenticatedObjectRoundTrip() throws Exception {
        final var src = new NestedObject("11111", "22222", "33333");
        final var json = mapper.writeValueAsString(src);
        final var token = maops.authenticate(json.getBytes(StandardCharsets.UTF_8));
        final var clear = maops.verifyAndDecode(token, Duration.ofSeconds(60), 1).value();
        Assertions.assertEquals(src, mapper.readValue(clear, NestedObject.class));
    }

    @Test
    public void encryptedRoundTrip() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.encryptThenAuthenticate(payload);
        Assertions.assertArrayEquals(payload, maops.authenticateThenDecrypt(token, Duration.ofSeconds(60), 1).value());
    }

    @Test
    public void encryptedObjectRoundTrip() throws Exception {
        final var src = new NestedObject("11111", "22222", "33333");
        final var json = mapper.writeValueAsString(src);
        final var token = maops.encryptThenAuthenticate(json.getBytes(StandardCharsets.UTF_8));
        final var clear = maops.authenticateThenDecrypt(token, Duration.ofSeconds(60), 1).value();
        Assertions.assertEquals(src, mapper.readValue(clear, NestedObject.class));
    }

    @Test
    public void encryptedTokenDoesNotExposeClearText() {
        final var token = maops.encryptThenAuthenticate("secret".getBytes(StandardCharsets.UTF_8));
        Assertions.assertFalse(token.contains("secret"));
    }

    @Test
    public void authenticatedReplayIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        maops.verifyAndDecode(token, Duration.ofSeconds(60), 1);
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(token, Duration.ofSeconds(60), 1));
    }

    @Test
    public void encryptedReplayIsRejected() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8));
        maops.authenticateThenDecrypt(token, Duration.ofSeconds(60), 1);
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt(token, Duration.ofSeconds(60), 1));
    }

    @Test
    public void authenticatedTamperingSaltIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(tamper(token, 0), Duration.ofSeconds(60), 1));
    }

    @Test
    public void authenticatedTamperingTimestampIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(tamper(token, 1), Duration.ofSeconds(60), 1));
    }

    @Test
    public void authenticatedTamperingPayloadIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(tamper(token, 2), Duration.ofSeconds(60), 1));
    }

    @Test
    public void authenticatedTamperingHmacIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(tamper(token, 3), Duration.ofSeconds(60), 1));
    }

    @Test
    public void encryptedTamperingIvIsRejected() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt(tamper(token, 0), Duration.ofSeconds(60), 1));
    }

    @Test
    public void encryptedTamperingTimestampIsRejected() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt(tamper(token, 1), Duration.ofSeconds(60), 1));
    }

    @Test
    public void encryptedTamperingCipherTextIsRejected() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt(tamper(token, 2), Duration.ofSeconds(60), 1));
    }

    @Test
    public void encryptedTamperingHmacIsRejected() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt(tamper(token, 3), Duration.ofSeconds(60), 1));
    }

    @Test
    public void authenticatedExpiredTokenIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        now.addAndGet(120_000L);
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(token, Duration.ofSeconds(60), 1));
    }

    @Test
    public void encryptedExpiredTokenIsRejected() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8));
        now.addAndGet(120_000L);
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt(token, Duration.ofSeconds(60), 1));
    }

    @Test
    public void wrongNumberOfPartsIsRejected() {
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode("a.b.c", Duration.ofSeconds(60), 1));
    }

    @Test
    public void nonNumericTimestampIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        final var parts = token.split("\\.");
        parts[1] = "not-a-number";
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(String.join(".", parts), Duration.ofSeconds(60), 1));
    }

    @Test
    public void nullValidityIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(token, null, 1));
    }

    @Test
    public void zeroValidityIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(token, Duration.ZERO, 1));
    }

    @Test
    public void negativeValidityIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(token, Duration.ofSeconds(-1), 1));
    }

    @Test
    public void negativeAttemptsIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(token, Duration.ofSeconds(60), -1));
    }

    @Test
    public void encryptedNullValidityIsRejected() {
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt("a.b.c.d", null, 1));
    }

    @Test
    public void encryptedZeroValidityIsRejected() {
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt("a.b.c.d", Duration.ZERO, 1));
    }

    @Test
    public void encryptedNegativeValidityIsRejected() {
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt("a.b.c.d", Duration.ofSeconds(-1), 1));
    }

    @Test
    public void encryptedNegativeAttemptsIsRejected() {
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt("a.b.c.d", Duration.ofSeconds(60), -1));
    }

    @Test
    public void encryptedWrongNumberOfPartsIsRejected() {
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt("a.b.c", Duration.ofSeconds(60), 1));
    }

    @Test
    public void encryptedNonNumericTimestampIsRejected() {
        final var token = maops.encryptThenAuthenticate("hello".getBytes(StandardCharsets.UTF_8));
        final var parts = token.split("\\.");
        parts[1] = "not-a-number";
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.authenticateThenDecrypt(String.join(".", parts), Duration.ofSeconds(60), 1));
    }

    @Test
    public void createRejectsShortAesKey() {
        Assertions.assertThrows(MessageAuthenticationError.class, () -> MessageAuthenticationOps.create(
                new InMemoryConsumedTokenStore(() -> 0L),
                new byte[16], new byte[64], new SecureRandom(), () -> 0L));
    }

    @Test
    public void createRejectsShortHmacKey() {
        Assertions.assertThrows(MessageAuthenticationError.class, () -> MessageAuthenticationOps.create(
                new InMemoryConsumedTokenStore(() -> 0L),
                new byte[32], new byte[32], new SecureRandom(), () -> 0L));
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
