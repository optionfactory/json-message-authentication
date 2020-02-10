package net.optionfactory.jma;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Base64;
import java.util.function.Supplier;
import javax.crypto.spec.SecretKeySpec;

public class MessageAuthenticationDeserializer extends JsonDeserializer<Object> {

    private final SecretKeySpec hmacKey;
    private final Base64.Decoder b64dec;
    private final Supplier<Long> clock;
    private final JavaType type;
    private final long validityMs;

    public MessageAuthenticationDeserializer(SecretKeySpec hmacKey, Base64.Decoder b64dec, Supplier<Long> clock, JavaType type, long validityMs) {
        this.hmacKey = hmacKey;
        this.b64dec = b64dec;
        this.clock = clock;
        this.type = type;
        this.validityMs = validityMs;
    }

    @Override
    public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException, JsonProcessingException {
        final String value = parser.getValueAsString();
        final String[] split = value.split("\\.");
        if (split.length != 4) {
            throw new MessageAuthenticationError("invalid parts");
        }
        final byte[] salt = b64dec.decode(split[0]);
        if (salt.length != 12) {
            throw new MessageAuthenticationError("invalid salt");
        }
        final long createdAt = Long.parseLong(split[1]);
        final long now = clock.get();
        if (validityMs != 0 && now - validityMs > createdAt) {
            throw new MessageAuthenticationError("expired");
        }

        final byte[] hmac = b64dec.decode(split[2]);
        final byte[] clearText = b64dec.decode(split[3]);

        if (!MessageAuthenticationOps.verify(salt, hmacKey, createdAt, hmac, clearText)) {
            throw new MessageAuthenticationError("tampering");
        }

        return ((ObjectMapper) parser.getCodec()).readValue(clearText, type);
    }

}
