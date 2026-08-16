package net.optionfactory.jma.stores;

/// Tracks consumed tokens to enforce single-use / replay protection. A token id
/// is consumed when first decoded and may be recycled to permit one more decode,
/// up to an `attempts` budget, or refunded to cancel a consume as if it never
/// happened (for upstream failures that prevented the token-guarded action from
/// running at all). Implementations must be thread-safe and make
/// consume/recycle/refund atomic per token id (consume must be exactly-once per
/// slot).
public interface ConsumedTokenStore {

    /// Blocks `messageId` as consumed.
    ///
    /// @return true if it was newly consumed (or re-consumed after a recycle);
    ///         false if already blocked or past `expiresAt`.
    boolean consume(String messageId, long expiresAt);

    /// Un-blocks `messageId` so it can be consumed again.
    ///
    /// @return false if the `attempts` budget is exhausted or the token is
    ///         unknown; idempotent (returns true) if already un-blocked.
    boolean recycle(String messageId, int attempts);

    /// Cancels one consume as if it never happened: decrements the consumed
    /// count and un-blocks `messageId`. Unlike [ #recycle ], the `attempts`
    /// budget is restored, so even a strict (`attempts = 1`) token returns to
    /// a virgin state.
    ///
    /// @return true if the token is (now) un-blocked with its budget restored;
    ///         idempotent when already refunded. False only for unknown ids
    ///         (e.g. purged after expiry), where the desired end state
    ///         (un-blocked) already holds.
    boolean refund(String messageId);
}
