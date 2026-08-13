package net.optionfactory.jma.stores;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

public class InMemoryConsumedTokenStore implements ConsumedTokenStore {

    private record State(long expiresAt, int consumed, boolean blocked) {

    }

    private final ConcurrentHashMap<String, State> store = new ConcurrentHashMap<>();
    private final PriorityBlockingQueue<Expiration> expirations = new PriorityBlockingQueue<>();
    private final AtomicBoolean isCleaning = new AtomicBoolean(false);
    private final Supplier<Long> clock;

    public InMemoryConsumedTokenStore(Supplier<Long> clock) {
        this.clock = clock;
    }

    @Override
    public boolean consume(String messageId, long expiresAt) {
        final long now = clock.get();

        cleanupExpired(now);

        if (now > expiresAt) {
            return false;
        }

        if (store.putIfAbsent(messageId, new State(expiresAt, 1, true)) == null) {
            expirations.offer(new Expiration(expiresAt, messageId));
            return true;
        }

        for (;;) {
            final State prev = store.get(messageId);
            if (prev == null || prev.blocked()) {
                return false;
            }
            if (store.replace(messageId, prev, new State(prev.expiresAt(), prev.consumed() + 1, true))) {
                return true;
            }
        }
    }

    @Override
    public boolean recycle(String messageId, int attempts) {
        for (;;) {
            final State prev = store.get(messageId);
            if (prev == null) {
                return false;
            }
            if (!prev.blocked()) {
                return true;
            }
            if (prev.consumed() >= attempts) {
                return false;
            }
            if (store.replace(messageId, prev, new State(prev.expiresAt(), prev.consumed(), false))) {
                return true;
            }
        }
    }

    private record Expiration(long expiresAt, String messageId) implements Comparable<Expiration> {

        @Override
        public int compareTo(Expiration o) {
            return Long.compare(this.expiresAt, o.expiresAt);
        }
    }

    private void cleanupExpired(long now) {
        if (!isCleaning.compareAndSet(false, true)) {
            return;
        }
        try {
            while (true) {
                final Expiration oldest = expirations.peek();
                if (oldest == null || oldest.expiresAt > now) {
                    break;
                }

                final Expiration expired = expirations.poll();
                if (expired != null) {
                    store.remove(expired.messageId);
                }
            }
        } finally {
            isCleaning.set(false);
        }
    }
}
