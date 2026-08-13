package net.optionfactory.jma;

import java.io.ByteArrayOutputStream;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

public class MessageAuthenticationEncryptedSerializer extends ValueSerializer<Object> {

    private final MessageAuthenticationOps ops;
    private final ValueSerializer<Object> delegate;

    public MessageAuthenticationEncryptedSerializer(MessageAuthenticationOps ops) {
        this(ops, null);
    }

    @SuppressWarnings("unchecked")
    public MessageAuthenticationEncryptedSerializer(MessageAuthenticationOps ops, ValueSerializer<?> delegate) {
        this.ops = ops;
        this.delegate = (ValueSerializer<Object>) delegate;
    }

    @Override
    public void resolve(SerializationContext context) {
        if (delegate != null) {
            delegate.resolve(context);
        }
    }

    @Override
    public void serialize(Object value, JsonGenerator gen, SerializationContext sp) {
        final var utf8os = new ByteArrayOutputStream();
        try (final var nestedGenerator = sp.tokenStreamFactory().createGenerator(gen.objectWriteContext(), utf8os)) {
            if (delegate != null) {
                delegate.serialize(value, nestedGenerator, sp);
            } else {
                nestedGenerator.writePOJO(value);
            }
        }
        final var authenticatedCipherText = ops.encryptThenAuthenticate(utf8os.toByteArray());
        gen.writePOJO(authenticatedCipherText);
    }

}
