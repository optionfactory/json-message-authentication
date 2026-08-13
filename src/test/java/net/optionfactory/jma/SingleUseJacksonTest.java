package net.optionfactory.jma;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import net.optionfactory.jma.MessageAuthentication.Mode;
import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import net.optionfactory.jma.stores.InMemoryConsumedTokenStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

public class SingleUseJacksonTest {

    private static final String AES = "hCVxn9jkw5WKeS2tjlO5bMmD4eHwm+P8daHUHesimnA";
    private static final String HMAC = "CRejIvb47whaMpIBNVAxym8Mbe33mbX0UbXaUJ2pKEaKiF8uRTlO5QzQTAPEhMKzZzuuGhJEaWcYGjti6Y4YZA";

    private MessageAuthenticationOps ops;
    private JsonMapper mapper;

    public record TwoFields(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String a, @MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String b) {
    }

    public record Nested(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String outer, Inner inner) {
    }

    public record Inner(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String value) {
    }

    public record StrictMixed(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String retryable, @MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 1) String strict) {
    }

    private static final TypeReference<SingleUse<TwoFields>> TWO = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<Nested>> NESTED = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<StrictMixed>> MIXED = new TypeReference<>() {
    };

    @BeforeEach
    public void setup() {
        this.ops = MessageAuthenticationOps.create(
                new InMemoryConsumedTokenStore(Clock.systemUTC()::millis),
                AES, HMAC, new SecureRandom(), System::currentTimeMillis, KeyEncoding.BASE_64);
        this.mapper = JsonMapper.builder().addModule(new MessageAuthenticationModule(ops)).build();
    }

    @Test
    public void singleUseWrapsDecodedBeanAndExposesValue() {
        final var src = new TwoFields("a", "b");
        final var json = mapper.writeValueAsString(src);
        final SingleUse<TwoFields> su = mapper.readValue(json, TWO);
        Assertions.assertEquals(src, su.value());
    }

    @Test
    public void recycleOnFailureAllowsRetry() {
        final var json = mapper.writeValueAsString(new TwoFields("a", "b"));
        final SingleUse<TwoFields> su1 = mapper.readValue(json, TWO);
        su1.recycle();
        final SingleUse<TwoFields> su2 = mapper.readValue(json, TWO);
        Assertions.assertEquals(new TwoFields("a", "b"), su2.value());
    }

    @Test
    public void successWithoutRecycleInvalidatesAll() {
        final var json = mapper.writeValueAsString(new TwoFields("a", "b"));
        mapper.readValue(json, TWO);
        Assertions.assertThrows(Exception.class, () -> mapper.readValue(json, TWO));
    }

    @Test
    public void nestedAnnotationsAggregateIntoOneHandle() {
        final var src = new Nested("o", new Inner("i"));
        final var json = mapper.writeValueAsString(src);
        final SingleUse<Nested> su = mapper.readValue(json, NESTED);
        su.recycle();
        final SingleUse<Nested> retry = mapper.readValue(json, NESTED);
        Assertions.assertEquals(src, retry.value());
    }

    @Test
    public void strictConstituentThrowsOnRecycle() {
        final var json = mapper.writeValueAsString(new StrictMixed("r", "s"));
        final SingleUse<StrictMixed> su = mapper.readValue(json, MIXED);
        Assertions.assertThrows(MessageAuthenticationError.class, su::recycle);
    }

    @Test
    public void rollbackRecyclesConsumedPartialsOnFailure() {
        final var json = mapper.writeValueAsString(new TwoFields("a", "b"));
        final JsonNode root = mapper.readTree(json);
        final String aToken = root.get("a").get("authmsg").asText();
        final var b = new StringBuilder(root.get("b").get("authmsg").asText());
        b.setCharAt(0, b.charAt(0) == 'A' ? 'B' : 'A');
        ((ObjectNode) root.get("b")).put("authmsg", b.toString());
        Assertions.assertThrows(Exception.class, () -> mapper.readValue(mapper.writeValueAsString(root), TWO));
        final var a = ops.verifyAndDecode(aToken, Duration.ofSeconds(60), 3);
        Assertions.assertEquals("\"a\"", new String(a.value(), java.nio.charset.StandardCharsets.UTF_8));
    }
}
