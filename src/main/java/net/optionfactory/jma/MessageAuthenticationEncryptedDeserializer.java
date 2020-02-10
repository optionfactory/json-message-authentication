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

public class MessageAuthenticationEncryptedDeserializer extends JsonDeserializer<Object> {

    private final SecretKeySpec aesKey;
    private final Base64.Decoder b64dec;
    private final Supplier<Long> clock;
    private final JavaType type;
    private final long validityMs;

    public MessageAuthenticationEncryptedDeserializer(SecretKeySpec aesKey ,Base64.Decoder b64dec, Supplier<Long> clock, JavaType type, long validityMs) {
        this.aesKey = aesKey;
        this.b64dec = b64dec;
        this.clock = clock;
        this.type = type;
        this.validityMs = validityMs;
    }

    @Override
    public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException, JsonProcessingException {
        final String value = parser.getValueAsString();
        final String[] split = value.split("\\.");
        if (split.length != 3) {
            throw new MessageAuthenticationError("invalid parts");
        }
        final byte[] iv = b64dec.decode(split[0]);
        if (iv.length != 12) {
            throw new MessageAuthenticationError("invalid iv");
        }
        final long timestamp = Long.parseLong(split[1]);
        final long now = clock.get();
        if (validityMs != 0 && now - validityMs > timestamp) {
            throw new MessageAuthenticationError("expired");
        }
        final byte[] cipherText = b64dec.decode(split[2]);

        final String clearText = MessageAuthenticationOps.decrypt(iv, aesKey, timestamp, cipherText);
        return ((ObjectMapper) parser.getCodec()).readValue(clearText, type);
    }

}
