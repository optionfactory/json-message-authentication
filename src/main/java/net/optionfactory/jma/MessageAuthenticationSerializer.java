package net.optionfactory.jma;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Supplier;
import javax.crypto.spec.SecretKeySpec;

public class MessageAuthenticationSerializer extends JsonSerializer<Object> {

    private final SecureRandom random;
    private final SecretKeySpec hmacKey;
    private final Base64.Encoder b64enc;
    private final Supplier<Long> clock;

    public MessageAuthenticationSerializer(SecretKeySpec hmacKey, SecureRandom random, Base64.Encoder b64enc, Supplier<Long> clock) {
        this.random = random;
        this.hmacKey = hmacKey;
        this.b64enc = b64enc;
        this.clock = clock;
    }

    @Override
    public void serialize(Object value, JsonGenerator gen, SerializerProvider sp) throws IOException {
        final ByteArrayOutputStream writer = new ByteArrayOutputStream();
        try (final JsonGenerator nestedGenerator = gen.getCodec().getFactory().createGenerator(writer)) {
            sp.defaultSerializeValue(value, nestedGenerator);
        }
        final long createdAt = clock.get();
        final byte[] salt = MessageAuthenticationOps.randomBytes(random, 12);
        final byte[] clearTextBytes = writer.toByteArray();
        final byte[] hmac = MessageAuthenticationOps.hmac(salt, hmacKey, createdAt, clearTextBytes);
        gen.writeStartObject();
        gen.writeObjectField("msg", value);
        gen.writeFieldName("authmsg");
        gen.writeObject(String.format("%s.%s.%s.%s",
                b64enc.encodeToString(salt),
                createdAt,
                b64enc.encodeToString(hmac),
                b64enc.encodeToString(clearTextBytes)
        ));
        gen.writeEndObject();
    }

}
