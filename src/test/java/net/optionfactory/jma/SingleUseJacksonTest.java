package net.optionfactory.jma;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
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

    public record EncTwo(@MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED, attempts = 3) String a, @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED, attempts = 3) String b) {
    }

    public record Nested(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String outer, Inner inner) {
    }

    public record Inner(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String value) {
    }

    public record Level1(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String v, Level2 inner) {
    }

    public record Level2(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String v, Level3 inner) {
    }

    public record Level3(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String v) {
    }

    public record StrictMixed(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String retryable, @MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 1) String strict) {
    }

    public record EncStrictMixed(@MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED, attempts = 3) String retryable, @MessageAuthentication(mode = Mode.AUTHENTICATED_ENCRYPTED, attempts = 1) String strict) {
    }

    public record NestedStrict(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3) String outer, InnerStrict inner) {
    }

    public record InnerStrict(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 1) String v) {
    }

    public record Lifecycle(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 2) String a, @MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 2) String b) {
    }

    public record MixedBudgets(@MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 2) String a, @MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 5) String b) {
    }

    public record Plain(String a, String b) {
    }

    @MessageAuthentication(mode = Mode.AUTHENTICATED, attempts = 3)
    public record ClassLevel(String f) {
    }

    private static final TypeReference<SingleUse<TwoFields>> TWO = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<EncTwo>> ENC_TWO = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<Nested>> NESTED = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<Level1>> LEVEL1 = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<StrictMixed>> MIXED = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<EncStrictMixed>> ENC_MIXED = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<NestedStrict>> NESTED_STRICT = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<Lifecycle>> LIFECYCLE = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<MixedBudgets>> MIXED_BUDGETS = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<Plain>> PLAIN = new TypeReference<>() {
    };
    private static final TypeReference<SingleUse<ClassLevel>> CLASS_LEVEL = new TypeReference<>() {
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
    public void strictConstituentRecycleThrowsTokenDepleted() {
        final var json = mapper.writeValueAsString(new StrictMixed("r", "s"));
        final SingleUse<StrictMixed> su = mapper.readValue(json, MIXED);
        Assertions.assertThrows(TokenDepleted.class, su::recycle);
    }

    @Test
    public void rollbackRecyclesConsumedPartialsOnFailure() {
        final var json = mapper.writeValueAsString(new TwoFields("a", "b"));
        final JsonNode root = mapper.readTree(json);
        final String aToken = root.get("a").get("authmsg").asString();
        final var b = new StringBuilder(root.get("b").get("authmsg").asString());
        b.setCharAt(0, b.charAt(0) == 'A' ? 'B' : 'A');
        ((ObjectNode) root.get("b")).put("authmsg", b.toString());
        Assertions.assertThrows(Exception.class, () -> mapper.readValue(mapper.writeValueAsString(root), TWO));
        final var a = ops.verifyAndDecode(aToken, 3);
        Assertions.assertEquals("\"a\"", new String(a.value(), StandardCharsets.UTF_8));
    }

    @Test
    public void encryptedSingleUseWrapsAndExposesValue() {
        final var src = new EncTwo("a", "b");
        final var json = mapper.writeValueAsString(src);
        final SingleUse<EncTwo> su = mapper.readValue(json, ENC_TWO);
        Assertions.assertEquals(src, su.value());
    }

    @Test
    public void encryptedRecycleAllowsRetry() {
        final var json = mapper.writeValueAsString(new EncTwo("a", "b"));
        final SingleUse<EncTwo> su1 = mapper.readValue(json, ENC_TWO);
        su1.recycle();
        final SingleUse<EncTwo> su2 = mapper.readValue(json, ENC_TWO);
        Assertions.assertEquals(new EncTwo("a", "b"), su2.value());
    }

    @Test
    public void encryptedSuccessInvalidatesAll() {
        final var json = mapper.writeValueAsString(new EncTwo("a", "b"));
        mapper.readValue(json, ENC_TWO);
        Assertions.assertThrows(Exception.class, () -> mapper.readValue(json, ENC_TWO));
    }

    @Test
    public void encryptedStrictConstituentRecycleThrowsTokenDepleted() {
        final var json = mapper.writeValueAsString(new EncStrictMixed("r", "s"));
        final SingleUse<EncStrictMixed> su = mapper.readValue(json, ENC_MIXED);
        Assertions.assertThrows(TokenDepleted.class, su::recycle);
    }

    @Test
    public void encryptedRollbackRecyclesPartials() {
        final var json = mapper.writeValueAsString(new EncTwo("a", "b"));
        final ObjectNode root = (ObjectNode) mapper.readTree(json);
        final String aToken = root.get("a").asString();
        final var b = new StringBuilder(root.get("b").asString());
        b.setCharAt(0, b.charAt(0) == 'A' ? 'B' : 'A');
        root.put("b", b.toString());
        Assertions.assertThrows(Exception.class, () -> mapper.readValue(mapper.writeValueAsString(root), ENC_TWO));
        final var a = ops.authenticateThenDecrypt(aToken, 3);
        Assertions.assertEquals("\"a\"", new String(a.value(), StandardCharsets.UTF_8));
    }

    @Test
    public void aggregateRespectsAttemptsBudget() {
        final var json = mapper.writeValueAsString(new Lifecycle("a", "b"));
        final SingleUse<Lifecycle> su1 = mapper.readValue(json, LIFECYCLE);
        su1.recycle();
        final SingleUse<Lifecycle> su2 = mapper.readValue(json, LIFECYCLE);
        Assertions.assertThrows(TokenDepleted.class, su2::recycle);
        Assertions.assertThrows(Exception.class, () -> mapper.readValue(json, LIFECYCLE));
    }

    @Test
    public void separateReadValuesHaveIndependentAccumulators() {
        final var json1 = mapper.writeValueAsString(new TwoFields("a", "b"));
        final var json2 = mapper.writeValueAsString(new TwoFields("c", "d"));
        final SingleUse<TwoFields> su1 = mapper.readValue(json1, TWO);
        final SingleUse<TwoFields> su2 = mapper.readValue(json2, TWO);
        su2.recycle();
        Assertions.assertThrows(Exception.class, () -> mapper.readValue(json1, TWO));
        su1.recycle();
        Assertions.assertEquals(new TwoFields("a", "b"), mapper.readValue(json1, TWO).value());
    }

    @Test
    public void deeplyNestedAnnotationsAggregate() {
        final var src = new Level1("a", new Level2("b", new Level3("c")));
        final var json = mapper.writeValueAsString(src);
        final SingleUse<Level1> su = mapper.readValue(json, LEVEL1);
        su.recycle();
        final SingleUse<Level1> retry = mapper.readValue(json, LEVEL1);
        Assertions.assertEquals(src, retry.value());
    }

    @Test
    public void strictFieldInNestedBeanRecycleThrowsTokenDepleted() {
        final var json = mapper.writeValueAsString(new NestedStrict("o", new InnerStrict("i")));
        final SingleUse<NestedStrict> su = mapper.readValue(json, NESTED_STRICT);
        Assertions.assertThrows(TokenDepleted.class, su::recycle);
    }

    @Test
    public void aggregateRecycleIsBoundedByTheSmallestBudget() {
        final var json = mapper.writeValueAsString(new MixedBudgets("a", "b"));
        final SingleUse<MixedBudgets> su1 = mapper.readValue(json, MIXED_BUDGETS);
        su1.recycle();
        final SingleUse<MixedBudgets> su2 = mapper.readValue(json, MIXED_BUDGETS);
        Assertions.assertThrows(TokenDepleted.class, su2::recycle);
    }

    @Test
    public void rollbackWhenFirstFieldFailsHasNothingToRecycle() {
        final var json = mapper.writeValueAsString(new TwoFields("a", "b"));
        final JsonNode root = mapper.readTree(json);
        final String aToken = root.get("a").get("authmsg").asString();
        ops.verifyAndDecode(aToken, 3);
        Assertions.assertThrows(Exception.class, () -> mapper.readValue(mapper.writeValueAsString(root), TWO));
    }

    @Test
    public void recycleCanBeInvokedMultipleTimesIdempotently() {
        final var json = mapper.writeValueAsString(new TwoFields("a", "b"));
        final SingleUse<TwoFields> su = mapper.readValue(json, TWO);
        su.recycle();
        su.recycle();
    }

    @Test
    public void emptyBeanWithNoAuthFieldsYieldsNoOpRecycle() {
        final var json = mapper.writeValueAsString(new Plain("a", "b"));
        final SingleUse<Plain> su = mapper.readValue(json, PLAIN);
        Assertions.assertEquals(new Plain("a", "b"), su.value());
        su.recycle();
    }

    @Test
    public void classLevelAnnotationAggregatesThroughSingleUse() {
        final var src = new ClassLevel("hello");
        final var json = mapper.writeValueAsString(src);
        final SingleUse<ClassLevel> su = mapper.readValue(json, CLASS_LEVEL);
        Assertions.assertEquals(src, su.value());
        su.recycle();
        final SingleUse<ClassLevel> retry = mapper.readValue(json, CLASS_LEVEL);
        Assertions.assertEquals(src, retry.value());
    }
}
