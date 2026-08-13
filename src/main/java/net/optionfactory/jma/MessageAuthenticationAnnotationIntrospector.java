package net.optionfactory.jma;

import tools.jackson.core.Version;
import tools.jackson.databind.AnnotationIntrospector;
import tools.jackson.databind.cfg.MapperConfig;
import tools.jackson.databind.introspect.Annotated;
import tools.jackson.databind.introspect.AnnotatedClass;

public class MessageAuthenticationAnnotationIntrospector extends AnnotationIntrospector {

    private final Version version;
    private final MessageAuthenticationOps ops;

    public MessageAuthenticationAnnotationIntrospector(Version version, MessageAuthenticationOps ops) {
        this.version = version;
        this.ops = ops;
    }

    @Override
    public Object findDeserializer(MapperConfig<?> config, Annotated am) {
        if (am instanceof AnnotatedClass) {
            return null;
        }
        final MessageAuthentication annotation = am.getAnnotation(MessageAuthentication.class);
        if (annotation == null) {
            return null;
        }

        final var validity = annotation.unit().getDuration().multipliedBy(annotation.validity());
        final int attempts = annotation.attempts();
        if (annotation.mode() == MessageAuthentication.Mode.AUTHENTICATED) {
            return new MessageAuthenticationDeserializer(ops, am.getType(), validity, attempts);
        }
        return new MessageAuthenticationEncryptedDeserializer(ops, am.getType(), validity, attempts);

    }

    @Override
    public Object findSerializer(MapperConfig<?> config, Annotated am) {
        if (am instanceof AnnotatedClass) {
            return null;
        }
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
