package net.optionfactory.jma;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.concurrent.atomic.AtomicLong;
import net.optionfactory.jma.MessageAuthentication.Mode;
import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import net.optionfactory.jma.stores.InMemoryConsumedTokenStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

public class MessageAuthenticationEncryptedTest {

    private JsonMapper mapper;

    public record RecordWithString(String field, @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED) String toBeEncrypted) {

    }

    public record RecordWithObject(String field, @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED) NestedObject toBeEncrypted) {

    }

    public record NestedObject(String value1, String value2, String value3) {

    }
    @BeforeEach
    public void setup() {
        final var maops = MessageAuthenticationOps.create(
                new InMemoryConsumedTokenStore(Clock.systemUTC()::millis),
                "hCVxn9jkw5WKeS2tjlO5bMmD4eHwm+P8daHUHesimnA=",
                "CRejIvb47whaMpIBNVAxym8Mbe33mbX0UbXaUJ2pKEaKiF8uRTlO5QzQTAPEhMKzZzuuGhJEaWcYGjti6Y4YZA==",
                new SecureRandom(),
                System::currentTimeMillis, KeyEncoding.BASE_64);
        this.mapper = JsonMapper.builder().addModule(new MessageAuthenticationModule(maops)).build();
    }

    @Test
    public void testString() {

        final var src = new RecordWithString("1", "11111");

        final var out = mapper.writeValueAsString(src);
        final var got = mapper.readValue(out, RecordWithString.class);

        System.out.format("serialized: %s%ndeserialized: %s%n", out, got);

        Assertions.assertFalse(out.contains(src.toBeEncrypted()));
        Assertions.assertEquals(src.toBeEncrypted(), got.toBeEncrypted());
    }

    @Test
    public void testObject() {
        final var src = new RecordWithObject("1", new NestedObject("11111", "22222", "33333"));

        final var out = mapper.writeValueAsString(src);
        final var got = mapper.readValue(out, RecordWithObject.class);

        System.out.format("serialized: %s%ndeserialized: %s%n", out, got);

        Assertions.assertFalse(out.contains(src.toBeEncrypted().value1()));
        Assertions.assertFalse(out.contains(src.toBeEncrypted().value2()));
        Assertions.assertFalse(out.contains(src.toBeEncrypted().value3()));
        Assertions.assertEquals(src.toBeEncrypted().value1(), got.toBeEncrypted().value1());
        Assertions.assertEquals(src.toBeEncrypted().value2(), got.toBeEncrypted().value2());
        Assertions.assertEquals(src.toBeEncrypted().value3(), got.toBeEncrypted().value3());
    }

    public record RecordWithStrictAttempts(String field, @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED, attempts = 1) String toBeEncrypted) {

    }

    @Test
    public void defaultAttemptsAllowsRepeatedDecodes() {
        final var src = new RecordWithString("1", "11111");
        final var out = mapper.writeValueAsString(src);
        mapper.readValue(out, RecordWithString.class);
        mapper.readValue(out, RecordWithString.class);
    }

    @Test
    public void attemptsOneRejectsRepeatedDecodes() {
        final var src = new RecordWithStrictAttempts("1", "11111");
        final var out = mapper.writeValueAsString(src);
        mapper.readValue(out, RecordWithStrictAttempts.class);
        Assertions.assertThrows(Exception.class, () -> mapper.readValue(out, RecordWithStrictAttempts.class));
    }

    @Test
    public void objectWhereTokenExpectedThrowsTokenMalformed() {
        final var thrown = Assertions.assertThrows(Exception.class, () -> mapper.readValue("{\"toBeEncrypted\":{\"a\":1}}", RecordWithString.class));
        Assertions.assertTrue(isTokenMalformed(thrown), "expected TokenMalformed, got: " + thrown);
    }

    @Test
    public void arrayWhereTokenExpectedThrowsTokenMalformed() {
        final var thrown = Assertions.assertThrows(Exception.class, () -> mapper.readValue("{\"toBeEncrypted\":[1,2]}", RecordWithString.class));
        Assertions.assertTrue(isTokenMalformed(thrown), "expected TokenMalformed, got: " + thrown);
    }

    private static boolean isTokenMalformed(Throwable t) {
        while (t != null) {
            if (t instanceof TokenMalformed) {
                return true;
            }
            t = t.getCause();
        }
        return false;
    }

    @Test
    public void expiredAnnotatedFieldFailsToDeserialize() {
        final var now = new AtomicLong(1_000_000L);
        final var maops = MessageAuthenticationOps.create(
                new InMemoryConsumedTokenStore(now::get),
                "hCVxn9jkw5WKeS2tjlO5bMmD4eHwm+P8daHUHesimnA=",
                "CRejIvb47whaMpIBNVAxym8Mbe33mbX0UbXaUJ2pKEaKiF8uRTlO5QzQTAPEhMKzZzuuGhJEaWcYGjti6Y4YZA==",
                new SecureRandom(), now::get, KeyEncoding.BASE_64);
        final var expiredMapper = JsonMapper.builder().addModule(new MessageAuthenticationModule(maops)).build();
        final var out = expiredMapper.writeValueAsString(new RecordWithString("1", "11111"));
        now.addAndGet(7L * 3_600_000L);
        Assertions.assertThrows(Exception.class, () -> expiredMapper.readValue(out, RecordWithString.class));
    }
}
