package net.optionfactory.jma;

import java.security.SecureRandom;
import java.time.Clock;
import net.optionfactory.jma.MessageAuthentication.Mode;
import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import net.optionfactory.jma.stores.InMemoryConsumedTokenStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

public class ClassLevelMessageAuthenticationTest {

    private JsonMapper mapper;

    @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED)
    public record Secret(String ssn, String account) {
    }

    @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED)
    public record Nested(Secret inner, String label) {
    }

    @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED)
    public record WithFieldAnnotation(String label, @MessageAuthentication(mode = Mode.AUTHENTICATED) String secret) {
    }

    @MessageAuthentication(mode = Mode.AUTHENTICATED)
    public record Authenticated(String ssn, String account) {
    }

    public record Container(Secret secret, String label) {
    }

    public record DoubleEncryptedOnSameType(@MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED) Secret secret) {
    }

    public record FieldEncryptedClassAuthenticated(@MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED) Authenticated auth) {
    }

    public record FieldAuthenticatedClassEncrypted(@MessageAuthentication(mode = Mode.AUTHENTICATED) Secret secret) {
    }

    public record DoubleAuthenticatedOnSameType(@MessageAuthentication(mode = Mode.AUTHENTICATED) Authenticated auth) {
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
    public void encryptedClassRoundtrips() {
        final var src = new Secret("123-45-6789", "ACC-001");

        final var out = mapper.writeValueAsString(src);

        Assertions.assertFalse(out.contains("123-45-6789"));
        Assertions.assertFalse(out.contains("ACC-001"));
        Assertions.assertFalse(out.contains("ssn"));
        Assertions.assertFalse(out.contains("account"));

        final var back = mapper.readValue(out, Secret.class);
        Assertions.assertEquals(src, back);
    }

    @Test
    public void nestedAnnotatedClassesRoundtrip() {
        final var src = new Nested(new Secret("123-45-6789", "ACC-001"), "my-label");

        final var out = mapper.writeValueAsString(src);

        Assertions.assertFalse(out.contains("123-45-6789"));
        Assertions.assertFalse(out.contains("ACC-001"));
        Assertions.assertFalse(out.contains("my-label"));

        final var back = mapper.readValue(out, Nested.class);
        Assertions.assertEquals(src, back);
    }

    @Test
    public void classLevelWithFieldLevelAnnotationRoundtrips() {
        final var src = new WithFieldAnnotation("my-label", "field-secret");

        final var out = mapper.writeValueAsString(src);

        Assertions.assertFalse(out.contains("my-label"));
        Assertions.assertFalse(out.contains("field-secret"));

        final var back = mapper.readValue(out, WithFieldAnnotation.class);
        Assertions.assertEquals(src, back);
    }

    @Test
    public void authenticatedClassRoundtrips() {
        final var src = new Authenticated("123-45-6789", "ACC-001");

        final var out = mapper.writeValueAsString(src);

        final var back = mapper.readValue(out, Authenticated.class);
        Assertions.assertEquals(src, back);
    }

    @Test
    public void classAnnotatedTypeAsFieldInUnannotatedContainer() {
        final var src = new Container(new Secret("123-45-6789", "ACC-001"), "my-label");

        final var out = mapper.writeValueAsString(src);

        Assertions.assertFalse(out.contains("123-45-6789"));
        Assertions.assertFalse(out.contains("ACC-001"));
        Assertions.assertTrue(out.contains("my-label"));

        final var back = mapper.readValue(out, Container.class);
        Assertions.assertEquals(src, back);
    }

    @Test
    public void collectionOfClassAnnotatedTypes() {
        final var src = java.util.List.of(
                new Secret("111-11-1111", "ACC-A"),
                new Secret("222-22-2222", "ACC-B"));

        final var out = mapper.writeValueAsString(src);

        Assertions.assertFalse(out.contains("111-11-1111"));
        Assertions.assertFalse(out.contains("222-22-2222"));

        final var back = mapper.readValue(out, new TypeReference<java.util.List<Secret>>() {});
        Assertions.assertEquals(src, back);
    }

    @Test
    public void bothFieldAndClassEncryptedOnSameType() {
        final var src = new DoubleEncryptedOnSameType(new Secret("123-45-6789", "ACC-001"));

        final var out = mapper.writeValueAsString(src);

        Assertions.assertFalse(out.contains("123-45-6789"));
        Assertions.assertFalse(out.contains("ACC-001"));
        Assertions.assertFalse(out.contains("ssn"));

        final var back = mapper.readValue(out, DoubleEncryptedOnSameType.class);
        Assertions.assertEquals(src, back);
    }

    @Test
    public void fieldEncryptedClassAuthenticated() {
        final var src = new FieldEncryptedClassAuthenticated(new Authenticated("123-45-6789", "ACC-001"));

        final var out = mapper.writeValueAsString(src);

        Assertions.assertFalse(out.contains("123-45-6789"));
        Assertions.assertFalse(out.contains("ACC-001"));

        final var back = mapper.readValue(out, FieldEncryptedClassAuthenticated.class);
        Assertions.assertEquals(src, back);
    }

    @Test
    public void fieldAuthenticatedClassEncrypted() {
        final var src = new FieldAuthenticatedClassEncrypted(new Secret("123-45-6789", "ACC-001"));

        final var out = mapper.writeValueAsString(src);

        Assertions.assertFalse(out.contains("123-45-6789"));
        Assertions.assertFalse(out.contains("ACC-001"));

        final var back = mapper.readValue(out, FieldAuthenticatedClassEncrypted.class);
        Assertions.assertEquals(src, back);
    }

    @Test
    public void bothFieldAndClassAuthenticatedOnSameType() {
        final var src = new DoubleAuthenticatedOnSameType(new Authenticated("123-45-6789", "ACC-001"));

        final var out = mapper.writeValueAsString(src);

        Assertions.assertTrue(out.contains("123-45-6789"));

        final var back = mapper.readValue(out, DoubleAuthenticatedOnSameType.class);
        Assertions.assertEquals(src, back);
    }
}
