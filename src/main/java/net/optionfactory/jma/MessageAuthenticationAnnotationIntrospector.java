package net.optionfactory.jma;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.introspect.Annotated;

public class MessageAuthenticationAnnotationIntrospector extends AnnotationIntrospector {

    private final Version version;
    private final MessageAuthenticationOps ops;

    public MessageAuthenticationAnnotationIntrospector(Version version, MessageAuthenticationOps ops) {
        this.version = version;
        this.ops = ops;
    }

    @Override
    public Object findDeserializer(Annotated am) {
        final MessageAuthentication annotation = am.getAnnotation(MessageAuthentication.class);
        if (annotation == null) {
            return null;
        }
        if (annotation.mode() == MessageAuthentication.Mode.AUTHENTICATED) {
            return new MessageAuthenticationDeserializer(ops, am.getType(), annotation.validityMs());
        }
        return new MessageAuthenticationEncryptedDeserializer(ops, am.getType(), annotation.validityMs());

    }

    @Override
    public Object findSerializer(Annotated am) {
        final MessageAuthentication annotation = am.getAnnotation(MessageAuthentication.class);
        if (annotation == null) {
            return null;
        }
        if (annotation.mode() == MessageAuthentication.Mode.AUTHENTICATED) {
            return new MessageAuthenticationSerializer(ops);
        }
        return new MessageAuthenticationEncryptedSerializer(ops);
    }

    @Override
    public Version version() {
        return version;
    }

}
