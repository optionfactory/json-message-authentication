package net.optionfactory.jma;

import java.util.ArrayList;
import java.util.List;

final class Accumulator {

    static final Object KEY = Accumulator.class;

    private final List<SingleUse.Usage> usages = new ArrayList<>();

    static void register(tools.jackson.databind.DeserializationContext context, SingleUse<?> singleUse) {
        final var acc = (Accumulator) context.getAttribute(KEY);
        if (acc != null) {
            acc.add(singleUse.usage());
        }
    }

    void add(SingleUse.Usage usage) {
        usages.add(usage);
    }

    void recycleConstituents() {
        MessageAuthenticationError firstFailure = null;
        for (final var u : usages) {
            try {
                u.recycle();
            } catch (MessageAuthenticationError e) {
                if (firstFailure == null) {
                    firstFailure = e;
                }
            }
        }
        if (firstFailure != null) {
            throw new TokenDepleted("bean is not retryable: one of its tokens could not be recycled");
        }
    }

    /// Refunds every constituent token. Lenient by design: deserialization
    /// failed, so the guarded action never ran and nothing should stay
    /// consumed — including strict (`attempts = 1`) tokens, which cannot be
    /// recycled.
    void refundConstituents() {
        for (final var u : usages) {
            try {
                u.refund();
            } catch (RuntimeException ignored) {
            }
        }
    }
}
