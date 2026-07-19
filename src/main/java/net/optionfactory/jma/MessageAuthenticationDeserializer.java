package net.optionfactory.jma;

import java.time.Duration;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ValueDeserializer;

public class MessageAuthenticationDeserializer extends ValueDeserializer<Object> {

    private final MessageAuthenticationOps ops;
    private final JavaType type;
    private final Duration validity;

    public MessageAuthenticationDeserializer(MessageAuthenticationOps ops, JavaType type, Duration validity) {
        this.ops = ops;
        this.type = type;
        this.validity = validity;
    }

    @Override
    public Object deserialize(JsonParser parser, DeserializationContext context) {
        final var value = parser.getValueAsString();
        final var verifiedBytes = ops.verifyAndDecode(value, validity);
        try (final var nestedParser = context.tokenStreamFactory().createParser(parser.objectReadContext(), verifiedBytes)) {
            return nestedParser.readValueAs(type);
        }
    }

}
