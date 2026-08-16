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
    public void refundRestoresVirginStateForStrictToken() {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        store.consume("a", 1000L);
        Assertions.assertTrue(store.refund("a"));
        Assertions.assertTrue(store.consume("a", 1000L), "token is decodable again: virgin state");
        Assertions.assertFalse(store.consume("a", 1000L), "and strictly single-use again");
        Assertions.assertFalse(store.recycle("a", 1), "the restored budget is fully spent by the second consume");
    }

    @Test
    public void refundIsIdempotent() {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        store.consume("a", 1000L);
        Assertions.assertTrue(store.refund("a"));
        Assertions.assertTrue(store.refund("a"));
    }

    @Test
    public void refundRejectsUnknownToken() {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        Assertions.assertFalse(store.refund("nope"));
    }

    @Test
    public void repeatedRefundsGrantNoExtraDecodes() {
        final var store = new InMemoryConsumedTokenStore(() -> 0L);
        store.consume("a", 1000L);
        store.refund("a");
        store.refund("a");
        Assertions.assertTrue(store.consume("a", 1000L));
        Assertions.assertFalse(store.consume("a", 1000L), "a double refund does not buy a second decode");
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
