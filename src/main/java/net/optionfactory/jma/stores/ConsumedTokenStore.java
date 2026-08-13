package net.optionfactory.jma.stores;

/// Tracks consumed tokens to enforce single-use / replay protection. A token id
/// is consumed when first decoded and may be recycled to permit one more decode,
/// up to an `attempts` budget. Implementations must be thread-safe and make
/// consume/recycle atomic per token id (consume must be exactly-once per slot).
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
}
