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
    public void strictSingleUseRecycleThrowsTokenDepleted() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.authenticate(payload, Duration.ofSeconds(5));
        final var first = maops.verifyAndDecode(token, 1);
        Assertions.assertArrayEquals(payload, first.value());
        Assertions.assertThrows(TokenDepleted.class, first::recycle);
    }

    @Test
    public void secondDecodeWithoutRecycleThrowsTokenAlreadyUsed() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.authenticate(payload, Duration.ofSeconds(5));
        maops.verifyAndDecode(token, 3);
        Assertions.assertThrows(TokenAlreadyUsed.class, () -> maops.verifyAndDecode(token, 3));
    }

    @Test
    public void recycleAllowsRetryUpToAttempts() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.authenticate(payload, Duration.ofSeconds(5));
        final int attempts = 3;
        for (int i = 0; i != attempts; i++) {
            final var su = maops.verifyAndDecode(token, attempts);
            Assertions.assertArrayEquals(payload, su.value());
            if (i != attempts - 1) {
                su.recycle();
            } else {
                Assertions.assertThrows(TokenDepleted.class, su::recycle);
            }
        }
    }

    @Test
    public void recycleIsIdempotentUntilRedecoded() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.authenticate(payload, Duration.ofSeconds(5));
        final var first = maops.verifyAndDecode(token, 3);
        first.recycle();
        first.recycle();
        final var second = maops.verifyAndDecode(token, 3);
        Assertions.assertArrayEquals(payload, second.value());
    }

    @Test
    public void encryptedTokensCanBeRecycled() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.encryptThenAuthenticate(payload, Duration.ofSeconds(5));
        final var first = maops.authenticateThenDecrypt(token, 2);
        Assertions.assertArrayEquals(payload, first.value());
        first.recycle();
        final var second = maops.authenticateThenDecrypt(token, 2);
        Assertions.assertArrayEquals(payload, second.value());
        Assertions.assertThrows(TokenDepleted.class, second::recycle);
    }

    @Test
    public void encryptedAttemptsZeroMeansInfinite() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.encryptThenAuthenticate(payload, Duration.ofSeconds(5));
        for (int i = 0; i != 5; i++) {
            final var su = maops.authenticateThenDecrypt(token, 0);
            Assertions.assertArrayEquals(payload, su.value());
            su.recycle();
        }
    }

    @Test
    public void attemptsZeroMeansInfinite() {
        final var payload = "hello".getBytes(StandardCharsets.UTF_8);
        final var token = maops.authenticate(payload, Duration.ofSeconds(5));
        for (int i = 0; i != 5; i++) {
            final var su = maops.verifyAndDecode(token, 0);
            Assertions.assertArrayEquals(payload, su.value());
            su.recycle();
        }
    }

    @Test
    public void negativeAttemptsIsRejectedAsIllegalArgument() {
        final var token = maops.authenticate("hello".getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(5));
        Assertions.assertThrows(IllegalArgumentException.class, () -> maops.verifyAndDecode(token, -1));
    }
}
