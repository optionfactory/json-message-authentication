package net.optionfactory.jma;

import java.time.Duration;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ValueDeserializer;

public class MessageAuthenticationEncryptedDeserializer extends ValueDeserializer<Object> {

    private final MessageAuthenticationOps ops;
    private final JavaType type;
    private final Duration validity;
    private final ValueDeserializer<Object> delegate;

    public MessageAuthenticationEncryptedDeserializer(MessageAuthenticationOps ops, JavaType type, Duration validity) {
        this(ops, type, validity, null);
    }

    @SuppressWarnings("unchecked")
    public MessageAuthenticationEncryptedDeserializer(MessageAuthenticationOps ops, Duration validity, ValueDeserializer<?> delegate) {
        this.ops = ops;
        this.type = null;
        this.validity = validity;
        this.delegate = (ValueDeserializer<Object>) delegate;
    }

    private MessageAuthenticationEncryptedDeserializer(MessageAuthenticationOps ops, JavaType type, Duration validity, ValueDeserializer<Object> delegate) {
        this.ops = ops;
        this.type = type;
        this.validity = validity;
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
        final String value = parser.getValueAsString();
        final var clearTextBytes = ops.authenticateThenDecrypt(value, validity);
        try (final var nestedParser = context.tokenStreamFactory().createParser(parser.objectReadContext(), clearTextBytes)) {
            if (delegate != null) {
                nestedParser.nextToken();
                return delegate.deserialize(nestedParser, context);
            }
            return nestedParser.readValueAs(type);
        }
    }

}
