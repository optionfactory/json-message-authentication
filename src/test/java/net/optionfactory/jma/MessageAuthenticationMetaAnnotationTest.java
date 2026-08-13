package net.optionfactory.jma;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import net.optionfactory.jma.MessageAuthentication.Mode;
import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import net.optionfactory.jma.stores.InMemoryConsumedTokenStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

public class MessageAuthenticationMetaAnnotationTest {

    private static final String AES = "hCVxn9jkw5WKeS2tjlO5bMmD4eHwm+P8daHUHesimnA";
    private static final String HMAC = "CRejIvb47whaMpIBNVAxym8Mbe33mbX0UbXaUJ2pKEaKiF8uRTlO5QzQTAPEhMKzZzuuGhJEaWcYGjti6Y4YZA";

    @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED, validity = 1, unit = ChronoUnit.HOURS, attempts = 1)
    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
    @java.lang.annotation.Target({java.lang.annotation.ElementType.FIELD, java.lang.annotation.ElementType.PARAMETER})
    public @interface EncryptedToken {
    }

    @MessageAuthentication(mode = Mode.AUTHENTICATED)
    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
    @java.lang.annotation.Target({java.lang.annotation.ElementType.FIELD, java.lang.annotation.ElementType.PARAMETER})
    public @interface AuthenticatedToken {
    }

    @MessageAuthentication(mode = Mode.AUTHENTICATED, validity = 1, unit = ChronoUnit.HOURS)
    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
    @java.lang.annotation.Target(java.lang.annotation.ElementType.TYPE)
    public @interface AuthenticatedType {
    }

    public record WithEncryptedToken(String field, @EncryptedToken String token) {
    }

    public record WithAuthenticatedToken(String field, @AuthenticatedToken String token) {
    }

    public record WithBoth(@MessageAuthentication(mode = Mode.AUTHENTICATED) @EncryptedToken String token) {
    }

    @AuthenticatedType
    public record AuthenticatedRecord(String a, String b) {
    }

    private JsonMapper mapper;

    @BeforeEach
    public void setup() {
        final var maops = MessageAuthenticationOps.create(
                new InMemoryConsumedTokenStore(Clock.systemUTC()::millis),
                AES, HMAC, new SecureRandom(), System::currentTimeMillis, KeyEncoding.BASE_64);
        this.mapper = JsonMapper.builder().addModule(new MessageAuthenticationModule(maops)).build();
    }

    @Test
    public void encryptedMetaAnnotationRoundTrips() {
        final var src = new WithEncryptedToken("1", "secret");
        final var out = mapper.writeValueAsString(src);
        Assertions.assertFalse(out.contains("secret"));
        Assertions.assertEquals(src, mapper.readValue(out, WithEncryptedToken.class));
    }

    @Test
    public void authenticatedMetaAnnotationRoundTrips() {
        final var src = new WithAuthenticatedToken("1", "value");
        final var out = mapper.writeValueAsString(src);
        Assertions.assertEquals(src, mapper.readValue(out, WithAuthenticatedToken.class));
    }

    @Test
    public void attemptsFlowThroughMetaAnnotation() {
        final var out = mapper.writeValueAsString(new WithEncryptedToken("1", "secret"));
        mapper.readValue(out, WithEncryptedToken.class);
        Assertions.assertThrows(Exception.class, () -> mapper.readValue(out, WithEncryptedToken.class));
    }

    @Test
    public void typeMetaAnnotationRoundTrips() {
        final var src = new AuthenticatedRecord("a", "b");
        final var out = mapper.writeValueAsString(src);
        Assertions.assertEquals(src, mapper.readValue(out, AuthenticatedRecord.class));
    }

    @Test
    public void directAnnotationTakesPrecedenceOverMeta() {
        final var out = mapper.writeValueAsString(new WithBoth("value"));
        final JsonNode token = mapper.readTree(out).get("token");
        Assertions.assertTrue(token.isObject(), "direct AUTHENTICATED should win, producing the {msg,authmsg} object form");
        Assertions.assertEquals("value", token.get("msg").asString());
    }
}
