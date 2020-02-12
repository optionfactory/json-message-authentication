package net.optionfactory.jma;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class MessageAuthenticationSerializer extends JsonSerializer<Object> {

    private final MessageAuthenticationOps ops;

    public MessageAuthenticationSerializer(MessageAuthenticationOps ops) {
        this.ops = ops;
    }

    @Override
    public void serialize(Object value, JsonGenerator gen, SerializerProvider sp) throws IOException {
        final var utf8os = new ByteArrayOutputStream();
        try (final var nestedGenerator = gen.getCodec().getFactory().createGenerator(utf8os)) {
            sp.defaultSerializeValue(value, nestedGenerator);
        }
        final var clearTextBytes = utf8os.toByteArray();
        final var authenticatedMessage = ops.authenticate(clearTextBytes);
        gen.writeStartObject();
        gen.writeObjectField("msg", value);
        gen.writeStringField("authmsg", authenticatedMessage);
        gen.writeEndObject();
    }

}
