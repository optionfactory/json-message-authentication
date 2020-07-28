package net.optionfactory.jma;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

public class MessageAuthenticationEncryptedDeserializer extends JsonDeserializer<Object> {

    private final MessageAuthenticationOps ops;
    private final JavaType type;
    private final long validityMs;

    public MessageAuthenticationEncryptedDeserializer(MessageAuthenticationOps ops, JavaType type, long validityMs) {
        this.ops = ops;
        this.type = type;
        this.validityMs = validityMs;
    }

    @Override
    public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException, JsonProcessingException {
        final String value = parser.getValueAsString();
        final var clearTextBytes = ops.authenticateThenDecrypt(value, validityMs);
        return ((ObjectMapper) parser.getCodec()).readValue(clearTextBytes, type);
    }

}
