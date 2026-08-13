package net.optionfactory.jma;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
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

    /// Finds a [MessageAuthentication] on `annotated`, either directly or as a
    /// meta-annotation on one of its annotations. A direct occurrence wins; if
    /// several annotations are meta-annotated, the first encountered is used.
    ///
    /// Both Jackson's merged view ([Annotated#annotations]) and the raw underlying
    /// element ([Annotated#getAnnotated]) are consulted, because the annotation
    /// may be reachable from only one of them (e.g. a record component's annotation
    /// is merged onto the accessor for serialization but lives on the field for
    /// deserialization).
    static MessageAuthentication find(Annotated annotated) {
        final var direct = annotated.getAnnotation(MessageAuthentication.class);
        if (direct != null) {
            return direct;
        }
        for (final Annotation a : annotated.annotations().toList()) {
            final var meta = a.annotationType().getAnnotation(MessageAuthentication.class);
            if (meta != null) {
                return meta;
            }
        }
        final AnnotatedElement element = annotated.getAnnotated();
        if (element != null) {
            for (final Annotation a : element.getAnnotations()) {
                final var meta = a.annotationType().getAnnotation(MessageAuthentication.class);
                if (meta != null) {
                    return meta;
                }
            }
        }
        return null;
    }

    @Override
    public Object findDeserializer(MapperConfig<?> config, Annotated am) {
        if (am instanceof AnnotatedClass) {
            return null;
        }
        final MessageAuthentication annotation = find(am);
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
        final MessageAuthentication annotation = find(am);
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
