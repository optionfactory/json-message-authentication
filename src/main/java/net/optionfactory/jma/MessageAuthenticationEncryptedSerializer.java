package net.optionfactory.jma;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;
import java.io.StringWriter;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Supplier;
import javax.crypto.spec.SecretKeySpec;

public class MessageAuthenticationEncryptedSerializer extends JsonSerializer<Object> {

    private final SecureRandom random;
    private final SecretKeySpec keySpec;
    private final Base64.Encoder b64enc;
    private final Supplier<Long> clock;

    public MessageAuthenticationEncryptedSerializer(SecretKeySpec keySpec, SecureRandom random, Base64.Encoder b64enc, Supplier<Long> clock) {
        this.random = random;
        this.keySpec = keySpec;
        this.b64enc = b64enc;
        this.clock = clock;
    }

    @Override
    public void serialize(Object value, JsonGenerator gen, SerializerProvider sp) throws IOException {
        final StringWriter writer = new StringWriter();
        try (final JsonGenerator nestedGenerator = gen.getCodec().getFactory().createGenerator(writer)) {
            sp.defaultSerializeValue(value, nestedGenerator);
        }
        final long createdAt = clock.get();
        final var iv = MessageAuthenticationOps.randomBytes(random, 12);
        final byte[] cipherText = MessageAuthenticationOps.encrypt(iv, keySpec, createdAt, writer.toString());
        gen.writeObject(String.format("%s.%s.%s", b64enc.encodeToString(iv), createdAt, b64enc.encodeToString(cipherText)));
    }

}
