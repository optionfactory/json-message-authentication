package net.optionfactory.jma;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import net.optionfactory.jma.MessageAuthentication.Mode;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class MessageAuthenticationEncryptedTest {

    private ObjectMapper mapper;

    public static class BeanWithString {

        public String field;

        @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED)
        public String toBeEncrypted;
    }

    public static class BeanWithObject {

        public String field;

        @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED)
        public NestedObject toBeEncrypted;

        public static class NestedObject {

            public String value1;
            public String value2;
            public String value3;
        }
    }

    @Before
    public void setup() {
        final var aesKey = Base64.getDecoder().decode("hCVxn9jkw5WKeS2tjlO5bMmD4eHwm+P8daHUHesimnA=");
        final var hmacKey = Base64.getDecoder().decode("CRejIvb47whaMpIBNVAxym8Mbe33mbX0UbXaUJ2pKEaKiF8uRTlO5QzQTAPEhMKzZzuuGhJEaWcYGjti6Y4YZA==");
        final var m = new ObjectMapper();
        m.registerModule(new MessageAuthenticationModule(aesKey, hmacKey, System::currentTimeMillis));
        this.mapper = m;
    }

    @Test
    public void testString() throws JsonProcessingException {

        final var src = new BeanWithString();
        src.field = "1";
        src.toBeEncrypted = "11111";

        final var out = mapper.writeValueAsString(src);
        final var got = mapper.readValue(out, BeanWithString.class);

        System.out.format("serialized: %s%ndeserialized: %s%n", out, got);

        Assert.assertFalse(out.contains(src.toBeEncrypted));
        Assert.assertEquals(src.toBeEncrypted, got.toBeEncrypted);
    }

    @Test
    public void testObject() throws JsonProcessingException {
        final var src = new BeanWithObject();
        src.field = "1";
        src.toBeEncrypted = new BeanWithObject.NestedObject();
        src.toBeEncrypted.value1 = "11111";
        src.toBeEncrypted.value2 = "22222";
        src.toBeEncrypted.value3 = "33333";

        final var out = mapper.writeValueAsString(src);
        final var got = mapper.readValue(out, BeanWithObject.class);

        System.out.format("serialized: %s%ndeserialized: %s%n", out, got);

        Assert.assertFalse(out.contains(src.toBeEncrypted.value1));
        Assert.assertFalse(out.contains(src.toBeEncrypted.value2));
        Assert.assertFalse(out.contains(src.toBeEncrypted.value3));
        Assert.assertEquals(src.toBeEncrypted.value1, got.toBeEncrypted.value1);
        Assert.assertEquals(src.toBeEncrypted.value2, got.toBeEncrypted.value2);
        Assert.assertEquals(src.toBeEncrypted.value3, got.toBeEncrypted.value3);
    }

}
