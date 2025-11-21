package net.optionfactory.jma;

import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import tools.jackson.databind.json.JsonMapper;

public class MaopsWithoutJsonTest {

    private JsonMapper mapper;
    private MessageAuthenticationOps maops;

    public record NestedObject(String value1, String value2, String value3) {
    }

    @Before
    public void setup() {
        this.maops = MessageAuthenticationOps.create(
                "hCVxn9jkw5WKeS2tjlO5bMmD4eHwm+P8daHUHesimnA=",
                "CRejIvb47whaMpIBNVAxym8Mbe33mbX0UbXaUJ2pKEaKiF8uRTlO5QzQTAPEhMKzZzuuGhJEaWcYGjti6Y4YZA==",
                new SecureRandom(),
                System::currentTimeMillis, KeyEncoding.BASE_64);
        this.mapper = new JsonMapper();
    }

    @Test
    public void testEncryptAuthenticateObject() throws IOException {
        final var src = new NestedObject("11111", "22222", "33333");
        final var out = mapper.writeValueAsString(src);
        final var asString = maops.encryptThenAuthenticate(out.getBytes(StandardCharsets.UTF_8));
        final var clearText = maops.authenticateThenDecrypt(asString, 5000);
        final var deserialized = mapper.readValue(clearText, NestedObject.class);
        Assert.assertEquals(src, deserialized);
    }

    @Test
    public void testAuthenticateObject() throws IOException {
        final var src = new NestedObject("11111", "22222", "33333");
        final var out = mapper.writeValueAsString(src);
        final var asString = maops.authenticate(out.getBytes(StandardCharsets.UTF_8));
        final var clearText = maops.verifyAndDecode(asString, 5000);
        final var deserialized = mapper.readValue(clearText, NestedObject.class);
        Assert.assertEquals(src, deserialized);
    }
}
