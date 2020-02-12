package net.optionfactory.jma;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.function.Supplier;

public class MessageAuthenticationEncryptedSerializer extends JsonSerializer<Object> {

    private final MessageAuthenticationOps ops;

    public MessageAuthenticationEncryptedSerializer(MessageAuthenticationOps ops) {
        this.ops = ops;
    }

    @Override
    public void serialize(Object value, JsonGenerator gen, SerializerProvider sp) throws IOException {
        final var utf8os = new ByteArrayOutputStream();
        try (final var nestedGenerator = gen.getCodec().getFactory().createGenerator(utf8os)) {
            sp.defaultSerializeValue(value, nestedGenerator);
        }
        final var authenticatedCipherText = ops.encryptThenAuthenticate(utf8os.toByteArray());
        gen.writeObject(authenticatedCipherText);
    }

}
