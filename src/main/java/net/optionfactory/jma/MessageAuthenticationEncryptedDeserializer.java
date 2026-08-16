package net.optionfactory.jma;

import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ValueDeserializer;

public class MessageAuthenticationEncryptedDeserializer extends ValueDeserializer<Object> {

    private final MessageAuthenticationOps ops;
    private final JavaType type;
    private final int attempts;
    private final ValueDeserializer<Object> delegate;

    public MessageAuthenticationEncryptedDeserializer(MessageAuthenticationOps ops, JavaType type, int attempts) {
        this(ops, type, attempts, null);
    }

    @SuppressWarnings("unchecked")
    public MessageAuthenticationEncryptedDeserializer(MessageAuthenticationOps ops, int attempts, ValueDeserializer<?> delegate) {
        this.ops = ops;
        this.type = null;
        this.attempts = attempts;
        this.delegate = (ValueDeserializer<Object>) delegate;
    }

    private MessageAuthenticationEncryptedDeserializer(MessageAuthenticationOps ops, JavaType type, int attempts, ValueDeserializer<Object> delegate) {
        this.ops = ops;
        this.type = type;
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
        final String value = parser.getValueAsString();
        final var singleUse = ops.authenticateThenDecrypt(value, attempts);
        Accumulator.register(context, singleUse);
        final var clearTextBytes = singleUse.value();
        try (final var nestedParser = context.tokenStreamFactory().createParser(parser.objectReadContext(), clearTextBytes)) {
            if (delegate != null) {
                nestedParser.nextToken();
                return delegate.deserialize(nestedParser, context);
            }
            return nestedParser.readValueAs(type);
        }
    }

}
