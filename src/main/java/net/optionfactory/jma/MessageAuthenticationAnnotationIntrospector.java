package net.optionfactory.jma;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.introspect.Annotated;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Supplier;
import javax.crypto.spec.SecretKeySpec;

public class MessageAuthenticationAnnotationIntrospector extends AnnotationIntrospector {

    private final Version version;
    private final SecretKeySpec aesKey;
    private final SecretKeySpec hmacKey;
    private final SecureRandom random;
    private final Base64.Encoder b64enc;
    private final Base64.Decoder b64dec;
    private final Supplier<Long> clock;

    public MessageAuthenticationAnnotationIntrospector(Version version, SecretKeySpec aesKey, SecretKeySpec hmacKey, SecureRandom random, Base64.Encoder b64enc, Base64.Decoder b64dec, Supplier<Long> clock) {
        this.version = version;
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
        this.random = random;
        this.b64enc = b64enc;
        this.b64dec = b64dec;
        this.clock = clock;
    }

    @Override
    public Object findDeserializer(Annotated am) {
        final MessageAuthenticationMessage annotation = am.getAnnotation(MessageAuthenticationMessage.class);
        if (annotation == null) {
            return null;
        }
        if (annotation.mode() == MessageAuthenticationMessage.Mode.AUTHENTICATED) {
            return new MessageAuthenticationDeserializer(hmacKey, b64dec, clock, am.getType(), annotation.validityMs());
        }
        return new MessageAuthenticationEncryptedDeserializer(aesKey, b64dec, clock, am.getType(), annotation.validityMs());

    }

    @Override
    public Object findSerializer(Annotated am) {
        final MessageAuthenticationMessage annotation = am.getAnnotation(MessageAuthenticationMessage.class);
        if (annotation == null) {
            return null;
        }
        if (annotation.mode() == MessageAuthenticationMessage.Mode.AUTHENTICATED) {
            return new MessageAuthenticationSerializer(hmacKey, random, b64enc, clock);
        }
        return new MessageAuthenticationEncryptedSerializer(aesKey, random, b64enc, clock);
    }

    @Override
    public Version version() {
        return version;
    }

}
