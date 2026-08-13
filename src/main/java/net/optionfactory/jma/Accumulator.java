package net.optionfactory.jma;

import java.util.ArrayList;
import java.util.List;

final class Accumulator {

    static final Object KEY = Accumulator.class;

    private final List<SingleUse.Recycler> recyclers = new ArrayList<>();

    static void register(tools.jackson.databind.DeserializationContext context, SingleUse<?> singleUse) {
        final var acc = (Accumulator) context.getAttribute(KEY);
        if (acc != null) {
            acc.add(singleUse.recycler());
        }
    }

    void add(SingleUse.Recycler recycler) {
        recyclers.add(recycler);
    }

    void recycleAll() {
        MessageAuthenticationError firstFailure = null;
        for (final var r : recyclers) {
            try {
                r.recycle();
            } catch (MessageAuthenticationError e) {
                if (firstFailure == null) {
                    firstFailure = e;
                }
            }
        }
        if (firstFailure != null) {
            throw new MessageAuthenticationError("bean is not retryable: one of its tokens could not be recycled");
        }
    }

    void rollback() {
        for (final var r : recyclers) {
            try {
                r.recycle();
            } catch (RuntimeException ignored) {
            }
        }
    }
}
