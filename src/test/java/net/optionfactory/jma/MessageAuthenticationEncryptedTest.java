package net.optionfactory.jma;

import java.security.SecureRandom;
import net.optionfactory.jma.MessageAuthentication.Mode;
import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
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
}
