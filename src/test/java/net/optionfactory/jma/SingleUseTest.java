package net.optionfactory.jma;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import net.optionfactory.jma.stores.InMemoryConsumedTokenStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SingleUseTest {

    private MessageAuthenticationOps maops;

    @BeforeEach
    public void setup() {
        this.maops = MessageAuthenticationOps.create(
                new InMemoryConsumedTokenStore(Clock.systemUTC()::millis),
                "hCVxn9jkw5WKeS2tjlO5bMmD4eHwm+P8daHUHesimnA=",
                "CRejIvb47whaMpIBNVAxym8Mbe33mbX0UbXaUJ2pKEaKiF8uRTlO5QzQTAPEhMKzZzuuGhJEaWcYGjti6Y4YZA==",
                new SecureRandom(),
                System::currentTimeMillis, KeyEncoding.BASE_64);
    }

    @Test
    public void strictSingleUseForbidsRecycle() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.authenticate(payload);
        final var first = maops.verifyAndDecode(token, Duration.ofSeconds(5), 1);
        Assertions.assertArrayEquals(payload, first.value());
        Assertions.assertThrows(MessageAuthenticationError.class, first::recycle);
    }

    @Test
    public void secondDecodeWithoutRecycleIsRejected() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.authenticate(payload);
        maops.verifyAndDecode(token, Duration.ofSeconds(5), 3);
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(token, Duration.ofSeconds(5), 3));
    }

    @Test
    public void recycleAllowsRetryUpToAttempts() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.authenticate(payload);
        final int attempts = 3;
        for (int i = 0; i != attempts; i++) {
            final var su = maops.verifyAndDecode(token, Duration.ofSeconds(5), attempts);
            Assertions.assertArrayEquals(payload, su.value());
            if (i != attempts - 1) {
                su.recycle();
            } else {
                Assertions.assertThrows(MessageAuthenticationError.class, su::recycle);
            }
        }
    }

    @Test
    public void recycleIsIdempotentUntilRedecoded() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.authenticate(payload);
        final var first = maops.verifyAndDecode(token, Duration.ofSeconds(5), 3);
        first.recycle();
        first.recycle();
        final var second = maops.verifyAndDecode(token, Duration.ofSeconds(5), 3);
        Assertions.assertArrayEquals(payload, second.value());
    }

    @Test
    public void encryptedTokensCanBeRecycled() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.encryptThenAuthenticate(payload);
        final var first = maops.authenticateThenDecrypt(token, Duration.ofSeconds(5), 2);
        Assertions.assertArrayEquals(payload, first.value());
        first.recycle();
        final var second = maops.authenticateThenDecrypt(token, Duration.ofSeconds(5), 2);
        Assertions.assertArrayEquals(payload, second.value());
        Assertions.assertThrows(MessageAuthenticationError.class, second::recycle);
    }

    @Test
    public void encryptedAttemptsZeroMeansInfinite() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.encryptThenAuthenticate(payload);
        for (int i = 0; i != 5; i++) {
            final var su = maops.authenticateThenDecrypt(token, Duration.ofSeconds(5), 0);
            Assertions.assertArrayEquals(payload, su.value());
            su.recycle();
        }
    }

    @Test
    public void attemptsZeroMeansInfinite() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.authenticate(payload);
        for (int i = 0; i != 5; i++) {
            final var su = maops.verifyAndDecode(token, Duration.ofSeconds(5), 0);
            Assertions.assertArrayEquals(payload, su.value());
            su.recycle();
        }
    }

    @Test
    public void attemptsNegativeIsRejected() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThrows(MessageAuthenticationError.class, () -> maops.verifyAndDecode(token, Duration.ofSeconds(5), -1));
    }
}
