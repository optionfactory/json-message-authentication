package net.optionfactory.jma;

import java.io.ByteArrayOutputStream;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

public class MessageAuthenticationEncryptedSerializer extends ValueSerializer<Object> {

    private final MessageAuthenticationOps ops;

    public MessageAuthenticationEncryptedSerializer(MessageAuthenticationOps ops) {
        this.ops = ops;
    }

    @Override
    public void serialize(Object value, JsonGenerator gen, SerializationContext sp) {
        final var utf8os = new ByteArrayOutputStream();
        try (final var nestedGenerator = sp.tokenStreamFactory().createGenerator(gen.objectWriteContext(), utf8os)) {
            nestedGenerator.writePOJO(value);
        }
        final var authenticatedCipherText = ops.encryptThenAuthenticate(utf8os.toByteArray());
        gen.writePOJO(authenticatedCipherText);
    }

}
