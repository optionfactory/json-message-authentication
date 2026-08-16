package net.optionfactory.jma;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

public class MessageAuthenticationSerializer extends ValueSerializer<Object> {

    private final MessageAuthenticationOps ops;
    private final Duration validity;
    private final ValueSerializer<Object> delegate;

    public MessageAuthenticationSerializer(MessageAuthenticationOps ops, Duration validity) {
        this(ops, validity, null);
    }

    @SuppressWarnings("unchecked")
    public MessageAuthenticationSerializer(MessageAuthenticationOps ops, Duration validity, ValueSerializer<?> delegate) {
        this.ops = ops;
        this.validity = validity;
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
        final var clearTextBytes = utf8os.toByteArray();
        final var authenticatedMessage = ops.authenticate(clearTextBytes, validity);
        gen.writeStartObject();
        gen.writeName("msg");
        if (delegate != null) {
            gen.writeRawValue(new String(clearTextBytes, StandardCharsets.UTF_8));
        } else {
            gen.writePOJO(value);
        }
        gen.writeStringProperty("authmsg", authenticatedMessage);
        gen.writeEndObject();
    }

}
