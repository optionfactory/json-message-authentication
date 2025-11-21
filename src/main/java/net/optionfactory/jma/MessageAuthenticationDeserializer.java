package net.optionfactory.jma;

import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ValueDeserializer;

public class MessageAuthenticationDeserializer extends ValueDeserializer<Object> {

    private final MessageAuthenticationOps ops;
    private final JavaType type;
    private final long validityMs;

    public MessageAuthenticationDeserializer(MessageAuthenticationOps ops, JavaType type, long validityMs) {
        this.ops = ops;
        this.type = type;
        this.validityMs = validityMs;
    }

    @Override
    public Object deserialize(JsonParser parser, DeserializationContext context) {
        final var value = parser.getValueAsString();
        final var verifiedBytes = ops.verifyAndDecode(value, validityMs);
        try (final var nestedParser = context.tokenStreamFactory().createParser(parser.objectReadContext(), verifiedBytes)) {
            return nestedParser.readValueAs(type);
        }
    }

}
