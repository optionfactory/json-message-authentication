package net.optionfactory.jma;

import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import net.optionfactory.jma.stores.InMemoryConsumedTokenStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ConsumedTokenStoreConcurrencyTest {

    @Test
    public void concurrentFirstConsumeHasExactlyOneWinner() throws Exception {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        final int threads = 50;
        final var ready = new CountDownLatch(threads);
        final var start = new CountDownLatch(1);
        final var wins = new AtomicInteger();
        try (final ExecutorService exec = Executors.newFixedThreadPool(threads)) {
            final var futures = new ArrayList<Future<?>>();
            for (int i = 0; i != threads; i++) {
                futures.add(exec.submit(() -> {
                    ready.countDown();
                    start.await();
                    if (store.consume("same", 10_000L)) {
                        wins.incrementAndGet();
                    }
                    return null;
                }));
            }
            ready.await();
            start.countDown();
            for (final var f : futures) {
                f.get();
            }
        }
        Assertions.assertEquals(1, wins.get());
    }

    @Test
    public void totalConsumesNeverExceedAttempts() throws Exception {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        final int attempts = 10;
        final int threads = 20;
        final int iterationsPerThread = 200;
        final var wins = new AtomicInteger();
        try (final ExecutorService exec = Executors.newFixedThreadPool(threads)) {
            final var futures = new ArrayList<Future<?>>();
            for (int t = 0; t != threads; t++) {
                futures.add(exec.submit(() -> {
                    for (int i = 0; i != iterationsPerThread; i++) {
                        if (store.consume("id", 1_000_000L)) {
                            wins.incrementAndGet();
                            store.recycle("id", attempts);
                        }
                    }
                    return null;
                }));
            }
            for (final var f : futures) {
                f.get();
            }
        }
        Assertions.assertEquals(attempts, wins.get());
    }

    @Test
    public void concurrentConsumesOfDistinctIdsAllSucceed() throws Exception {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        final int n = 200;
        final var wins = new AtomicInteger();
        try (final ExecutorService exec = Executors.newFixedThreadPool(8)) {
            final var futures = new ArrayList<Future<?>>();
            for (int i = 0; i != n; i++) {
                final String id = "id-" + i;
                futures.add(exec.submit(() -> {
                    if (store.consume(id, 1_000_000L)) {
                        wins.incrementAndGet();
                    }
                    return null;
                }));
            }
            for (final var f : futures) {
                f.get();
            }
        }
        Assertions.assertEquals(n, wins.get());
    }

    @Test
    public void concurrentRecycleAllowsExactlyOneSubsequentConsume() throws Exception {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        Assertions.assertTrue(store.consume("id", 1_000_000L));
        final int threads = 20;
        try (final ExecutorService exec = Executors.newFixedThreadPool(threads)) {
            final var futures = new ArrayList<Future<?>>();
            for (int i = 0; i != threads; i++) {
                futures.add(exec.submit(() -> store.recycle("id", 5)));
            }
            for (final var f : futures) {
                f.get();
            }
        }
        Assertions.assertTrue(store.consume("id", 1_000_000L));
        Assertions.assertFalse(store.consume("id", 1_000_000L));
    }

    @Test
    public void concurrentMixedOpsNeverCorruptState() throws Exception {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        final int ids = 16;
        final int attempts = 4;
        final var wins = new AtomicInteger();
        try (final ExecutorService exec = Executors.newFixedThreadPool(16)) {
            final var futures = new ArrayList<Future<?>>();
            for (int t = 0; t != 16; t++) {
                futures.add(exec.submit(() -> {
                    for (int i = 0; i != 500; i++) {
                        final String id = "id-" + (i % ids);
                        if (store.consume(id, 1_000_000L)) {
                            wins.incrementAndGet();
                            store.recycle(id, attempts);
                        }
                    }
                    return null;
                }));
            }
            for (final var f : futures) {
                f.get();
            }
        }
        Assertions.assertEquals(ids * attempts, wins.get());
    }
}
