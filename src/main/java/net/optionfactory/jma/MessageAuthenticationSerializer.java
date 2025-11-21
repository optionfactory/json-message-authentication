package net.optionfactory.jma;

import java.io.ByteArrayOutputStream;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

public class MessageAuthenticationSerializer extends ValueSerializer<Object> {

    private final MessageAuthenticationOps ops;

    public MessageAuthenticationSerializer(MessageAuthenticationOps ops) {
        this.ops = ops;
    }

    @Override
    public void serialize(Object value, JsonGenerator gen, SerializationContext sp) {
        final var utf8os = new ByteArrayOutputStream();

        
        try (final var nestedGenerator = sp.tokenStreamFactory().createGenerator(gen.objectWriteContext(), utf8os)) {
            nestedGenerator.writePOJO(value);
        }
        final var clearTextBytes = utf8os.toByteArray();
        final var authenticatedMessage = ops.authenticate(clearTextBytes);
        gen.writeStartObject();
        gen.writePOJOProperty("msg", value);
        gen.writeStringProperty("authmsg", authenticatedMessage);
        gen.writeEndObject();
    }

}
