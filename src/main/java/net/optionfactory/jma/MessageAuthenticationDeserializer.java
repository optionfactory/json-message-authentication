package net.optionfactory.jma;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

public class MessageAuthenticationDeserializer extends JsonDeserializer<Object> {

    private final MessageAuthenticationOps ops;
    private final JavaType type;
    private final long validityMs;

    public MessageAuthenticationDeserializer(MessageAuthenticationOps ops, JavaType type, long validityMs) {
        this.ops = ops;
        this.type = type;
        this.validityMs = validityMs;
    }

    @Override
    public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException, JsonProcessingException {
        final var value = parser.getValueAsString();
        final var verifiedBytes = ops.verifyAndDecode(value, validityMs);
        return ((ObjectMapper) parser.getCodec()).readValue(verifiedBytes, type);
    }

}
