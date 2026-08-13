package net.optionfactory.jma;

import tools.jackson.databind.DeserializationConfig;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.deser.Deserializers;
import tools.jackson.core.JsonParser;

/// Deserializes a {@code SingleUse<T>} by decoding {@code T} while collecting
/// every per-field recycler into an [Accumulator]. The resulting
/// [SingleUse] wraps the decoded bean and a composite recycler that recycles
/// ALL tokens consumed for the bean. If decoding {@code T} fails partway, the
/// already-consumed tokens are recycled (rolled back) before rethrowing.
public class SingleUseDeserializer extends ValueDeserializer<Object> {

    private final JavaType innerType;

    public SingleUseDeserializer() {
        this(null);
    }

    public SingleUseDeserializer(JavaType innerType) {
        this.innerType = innerType;
    }

    @Override
    public ValueDeserializer<?> createContextual(DeserializationContext context, tools.jackson.databind.BeanProperty property) {
        final JavaType type = property == null ? context.getContextualType() : property.getType();
        if (type == null || type.containedTypeCount() < 1) {
            return this;
        }
        return new SingleUseDeserializer(type.containedTypeOrUnknown(0));
    }

    @Override
    public Object deserialize(JsonParser parser, DeserializationContext context) {
        if (innerType == null) {
            throw new IllegalArgumentException("SingleUse<?> requires a concrete type parameter");
        }
        final var accumulator = new Accumulator();
        context.setAttribute(Accumulator.KEY, accumulator);
        try {
            final ValueDeserializer<Object> inner = (ValueDeserializer<Object>) context.findContextualValueDeserializer(innerType, null);
            final var bean = inner.deserialize(parser, context);
            return new SingleUse<>(bean, accumulator::recycleAll);
        } catch (RuntimeException e) {
            accumulator.rollback();
            throw e;
        }
    }

    public static class Registrar implements Deserializers {

        @Override
        public ValueDeserializer<?> findBeanDeserializer(JavaType type, DeserializationConfig config, tools.jackson.databind.BeanDescription.Supplier beanDesc) {
            if (type.getRawClass() == SingleUse.class) {
                return new SingleUseDeserializer(type.containedTypeOrUnknown(0));
            }
            return null;
        }

        @Override
        public boolean hasDeserializerFor(DeserializationConfig config, Class<?> valueType) {
            return valueType == SingleUse.class;
        }
    }
}
