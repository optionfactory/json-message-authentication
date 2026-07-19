package net.optionfactory.jma.singleuse;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

public class InMemorySingleUseStore implements SingleUseStore {

    private final ConcurrentHashMap<String, Long> store = new ConcurrentHashMap<>();
    private final PriorityBlockingQueue<Expiration> expirations = new PriorityBlockingQueue<>();
    private final AtomicBoolean isCleaning = new AtomicBoolean(false);
    private final Supplier<Long> clock;

    public InMemorySingleUseStore(Supplier<Long> clock) {
        this.clock = clock;
    }

    @Override
    public boolean checkAndStore(String messageId, long expirationMs) {
        final long now = clock.get();

        cleanupExpired(now);

        if (now > expirationMs) {
            return false;
        }

        if (store.putIfAbsent(messageId, expirationMs) == null) {
            expirations.offer(new Expiration(expirationMs, messageId));
            return true;
        }

        return false;
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
                    store.remove(expired.messageId, expired.expiresAt);
                }
            }
        } finally {
            isCleaning.set(false);
        }
    }
}
