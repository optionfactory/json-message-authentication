package net.optionfactory.jma;

import java.time.Duration;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ValueDeserializer;

public class MessageAuthenticationDeserializer extends ValueDeserializer<Object> {

    private final MessageAuthenticationOps ops;
    private final JavaType type;
    private final Duration validity;
    private final int attempts;
    private final ValueDeserializer<Object> delegate;

    public MessageAuthenticationDeserializer(MessageAuthenticationOps ops, JavaType type, Duration validity, int attempts) {
        this(ops, type, validity, attempts, null);
    }

    @SuppressWarnings("unchecked")
    public MessageAuthenticationDeserializer(MessageAuthenticationOps ops, Duration validity, int attempts, ValueDeserializer<?> delegate) {
        this.ops = ops;
        this.type = null;
        this.validity = validity;
        this.attempts = attempts;
        this.delegate = (ValueDeserializer<Object>) delegate;
    }

    private MessageAuthenticationDeserializer(MessageAuthenticationOps ops, JavaType type, Duration validity, int attempts, ValueDeserializer<Object> delegate) {
        this.ops = ops;
        this.type = type;
        this.validity = validity;
        this.attempts = attempts;
        this.delegate = delegate;
    }

    @Override
    public void resolve(DeserializationContext context) {
        if (delegate != null) {
            delegate.resolve(context);
        }
    }

    @Override
    public Object deserialize(JsonParser parser, DeserializationContext context) {
        final var token = parser.currentToken();
        final String value;
        if (token == JsonToken.START_OBJECT) {
            value = readAuthmsgField(parser);
        } else {
            value = parser.getValueAsString();
        }
        final var verifiedBytes = ops.verifyAndDecode(value, validity, attempts).value();
        try (final var nestedParser = context.tokenStreamFactory().createParser(parser.objectReadContext(), verifiedBytes)) {
            if (delegate != null) {
                nestedParser.nextToken();
                return delegate.deserialize(nestedParser, context);
            }
            return nestedParser.readValueAs(type);
        }
    }

    private static String readAuthmsgField(JsonParser parser) {
        String authmsg = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            final var fieldName = parser.currentName();
            parser.nextToken();
            if ("authmsg".equals(fieldName)) {
                authmsg = parser.getValueAsString();
            } else {
                parser.skipChildren();
            }
        }
        if (authmsg == null) {
            throw new MessageAuthenticationError("missing authmsg");
        }
        return authmsg;
    }

}
