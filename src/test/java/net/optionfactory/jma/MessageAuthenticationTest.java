package net.optionfactory.jma;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.SecureRandom;
import net.optionfactory.jma.MessageAuthentication.Mode;
import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class MessageAuthenticationTest {

    private ObjectMapper mapper;

    public record RecordWithString(String field, @MessageAuthentication(mode = Mode.AUTHENTICATED) String toBeAuthenticated) {

    }

    @Before
    public void setup() {
        final var maops = MessageAuthenticationOps.create(
                "hCVxn9jkw5WKeS2tjlO5bMmD4eHwm+P8daHUHesimnA",
                "CRejIvb47whaMpIBNVAxym8Mbe33mbX0UbXaUJ2pKEaKiF8uRTlO5QzQTAPEhMKzZzuuGhJEaWcYGjti6Y4YZA",
                new SecureRandom(),
                System::currentTimeMillis, KeyEncoding.BASE_64);

        final var m = new ObjectMapper();
        m.registerModule(new MessageAuthenticationModule(maops));
        this.mapper = m;
    }

    @Test
    public void exampleWithAuthenticatedField() throws JsonProcessingException {

        final var src = new RecordWithString("1", "11111");

        //server serializes something like:
        // {"field":"1","toBeAuthenticated":{"msg":"11111","authmsg":"slplEh02MR5ma0MH.1581272779124.Vna0jlMhqL3gXSmekglnEa31h-UdvwVgvlSEuq55BwY.IjExMTExIg"}}
        final var out = mapper.writeValueAsString(src);
        //client can use "msg" and can send back "auth" when needed
        final var toBeModified = mapper.readValue(out, ObjectNode.class);
        toBeModified.set("toBeAuthenticated", toBeModified.get("toBeAuthenticated").get("authmsg"));
        final String got = new ObjectMapper().writeValueAsString(toBeModified);
        //server received the auth field, verifies it and it gets automatically mapped
        final var gotFromClient = mapper.readValue(got, RecordWithString.class);
        Assert.assertEquals("1", gotFromClient.field());
        Assert.assertEquals("11111", gotFromClient.toBeAuthenticated());

    }

}
