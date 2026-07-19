package net.optionfactory.jma;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import net.optionfactory.jma.MessageAuthentication.Mode;
import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import net.optionfactory.jma.singleuse.InMemorySingleUseStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

public class MessageAuthenticationTest {

    private JsonMapper mapper;

    public record RecordWithString(String field, @MessageAuthentication(mode = Mode.AUTHENTICATED) String toBeAuthenticated) {

    }

    @BeforeEach
    public void setup() {
        final var maops = MessageAuthenticationOps.create(
                new InMemorySingleUseStore(Clock.systemUTC()::millis),
                "hCVxn9jkw5WKeS2tjlO5bMmD4eHwm+P8daHUHesimnA",
                "CRejIvb47whaMpIBNVAxym8Mbe33mbX0UbXaUJ2pKEaKiF8uRTlO5QzQTAPEhMKzZzuuGhJEaWcYGjti6Y4YZA",
                new SecureRandom(),
                System::currentTimeMillis, KeyEncoding.BASE_64);

        this.mapper = JsonMapper.builder()
                .addModule(new MessageAuthenticationModule(maops)).build();
    }

    @Test
    public void exampleWithAuthenticatedField() {

        final var src = new RecordWithString("1", "11111");

        //server serializes something like:
        // {"field":"1","toBeAuthenticated":{"msg":"11111","authmsg":"slplEh02MR5ma0MH.1581272779124.Vna0jlMhqL3gXSmekglnEa31h-UdvwVgvlSEuq55BwY.IjExMTExIg"}}
        final var out = mapper.writeValueAsString(src);
        //client can use "msg" and can send back "authmsg" when needed
        final var toBeModified = mapper.readValue(out, ObjectNode.class);
        toBeModified.set("toBeAuthenticated", toBeModified.get("toBeAuthenticated").get("authmsg"));
        final String got = new JsonMapper().writeValueAsString(toBeModified);
        //server received the auth field, verifies it and it gets automatically mapped
        final var gotFromClient = mapper.readValue(got, RecordWithString.class);
        Assertions.assertEquals("1", gotFromClient.field());
        Assertions.assertEquals("11111", gotFromClient.toBeAuthenticated());

    }

    public record RecordWithAnnotatedObject(String field, @MessageAuthentication(mode = Mode.AUTHENTICATED) AnnotatedObject toBeAuthenticated) {

    }

    public record AnnotatedObject(@JsonFormat(shape = JsonFormat.Shape.NUMBER) Instant value) {

    }

    @Test
    public void testNestedObjectWithAnnotations() {
        final var src = new RecordWithAnnotatedObject("1", new AnnotatedObject(Instant.parse("1970-01-01T00:00:00.000Z")));

        final var out = mapper.writeValueAsString(src);

        final var toBeModified = mapper.readValue(out, ObjectNode.class);
        toBeModified.set("toBeAuthenticated", toBeModified.get("toBeAuthenticated").get("authmsg"));

        final var got = mapper.readValue(new JsonMapper().writeValueAsString(toBeModified), RecordWithAnnotatedObject.class);

        Assertions.assertEquals(src.toBeAuthenticated().value(), got.toBeAuthenticated().value());
    }

}
