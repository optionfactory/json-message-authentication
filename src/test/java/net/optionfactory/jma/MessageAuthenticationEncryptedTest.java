package net.optionfactory.jma;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.SecureRandom;
import net.optionfactory.jma.MessageAuthentication.Mode;
import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class MessageAuthenticationEncryptedTest {

    private ObjectMapper mapper;

    public record RecordWithString(String field, @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED) String toBeEncrypted) {

    }

    public record RecordWithObject(String field, @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED)
            NestedObject toBeEncrypted) {

    }

    public record NestedObject(String value1, String value2, String value3) {

    }

    @Before
    public void setup() {
        final var maops = MessageAuthenticationOps.create(
                "hCVxn9jkw5WKeS2tjlO5bMmD4eHwm+P8daHUHesimnA=",
                "CRejIvb47whaMpIBNVAxym8Mbe33mbX0UbXaUJ2pKEaKiF8uRTlO5QzQTAPEhMKzZzuuGhJEaWcYGjti6Y4YZA==",
                new SecureRandom(),
                System::currentTimeMillis, KeyEncoding.BASE_64);
        final var m = new ObjectMapper();
        m.registerModule(new MessageAuthenticationModule(maops));
        this.mapper = m;
    }

    @Test
    public void testString() throws JsonProcessingException {

        final var src = new RecordWithString("1", "11111");

        final var out = mapper.writeValueAsString(src);
        final var got = mapper.readValue(out, RecordWithString.class);

        System.out.format("serialized: %s%ndeserialized: %s%n", out, got);

        Assert.assertFalse(out.contains(src.toBeEncrypted()));
        Assert.assertEquals(src.toBeEncrypted(), got.toBeEncrypted());
    }

    @Test
    public void testObject() throws JsonProcessingException {
        final var src = new RecordWithObject("1", new NestedObject("11111", "22222", "33333"));

        final var out = mapper.writeValueAsString(src);
        final var got = mapper.readValue(out, RecordWithObject.class);

        System.out.format("serialized: %s%ndeserialized: %s%n", out, got);

        Assert.assertFalse(out.contains(src.toBeEncrypted().value1()));
        Assert.assertFalse(out.contains(src.toBeEncrypted().value2()));
        Assert.assertFalse(out.contains(src.toBeEncrypted().value3()));
        Assert.assertEquals(src.toBeEncrypted().value1(), got.toBeEncrypted().value1());
        Assert.assertEquals(src.toBeEncrypted().value2(), got.toBeEncrypted().value2());
        Assert.assertEquals(src.toBeEncrypted().value3(), got.toBeEncrypted().value3());
    }

}
