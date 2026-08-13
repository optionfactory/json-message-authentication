package net.optionfactory.jma;

import java.util.concurrent.atomic.AtomicLong;
import net.optionfactory.jma.stores.InMemoryConsumedTokenStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ConsumedTokenStoreTest {

    @Test
    public void consumeAcceptsNewToken() {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        Assertions.assertTrue(store.consume("a", 1000L));
    }

    @Test
    public void consumeRejectsAlreadyBlockedToken() {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        store.consume("a", 1000L);
        Assertions.assertFalse(store.consume("a", 1000L));
    }

    @Test
    public void consumeAcceptsRecycledTokenAndCountsTheAttempt() {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        store.consume("a", 1000L);
        store.recycle("a", 3);
        Assertions.assertTrue(store.consume("a", 1000L));
        Assertions.assertFalse(store.recycle("a", 2));
    }

    @Test
    public void recycleUnblocksBlockedTokenUnderBudget() {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        store.consume("a", 1000L);
        Assertions.assertTrue(store.recycle("a", 3));
        Assertions.assertTrue(store.consume("a", 1000L));
    }

    @Test
    public void recycleIsIdempotentWhenAlreadyUnblocked() {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        store.consume("a", 1000L);
        store.recycle("a", 3);
        Assertions.assertTrue(store.recycle("a", 3));
    }

    @Test
    public void recycleRejectsWhenBudgetExhausted() {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        store.consume("a", 1000L);
        Assertions.assertFalse(store.recycle("a", 1));
    }

    @Test
    public void recycleRejectsUnknownToken() {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        Assertions.assertFalse(store.recycle("nope", 3));
    }

    @Test
    public void consumeRejectsExpiredToken() {
        final var now = new AtomicLong(0L);
        final var store = new InMemoryConsumedTokenStore(now::get);
        now.set(200L);
        Assertions.assertFalse(store.consume("a", 100L));
    }

    @Test
    public void expiredEntriesArePurgedOnSubsequentOp() {
        final var now = new AtomicLong(0L);
        final var store = new InMemoryConsumedTokenStore(now::get);
        store.consume("a", 100L);
        now.set(200L);
        store.consume("b", 300L);
        Assertions.assertFalse(store.recycle("a", 3));
    }
}
