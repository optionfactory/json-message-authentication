package net.optionfactory.jma;

/// Result of decoding a single-use token. Holds the decoded [ #value() ] and a
/// [ #usage() ] handle with two mutually exclusive recovery actions:
///
/// - [ Usage#recycle ] — the guarded action **ran and failed**: re-block later,
///   but the attempt stays spent. Bounded by the token's `attempts` budget;
///   throws [TokenDepleted] when the budget is exhausted.
/// - [ Usage#refund ] — an **upstream failure prevented the action from running
///   at all**: the attempt is given back, so even a strict (`attempts = 1`)
///   token returns to a virgin state.
///
/// The token is blocked at decode time and each decode consumes one attempt
/// (so concurrent replays are rejected on the happy path). On success the
/// caller does nothing — the token stays blocked and any further decode is
/// rejected.
///
/// Misuse warning: calling [ Usage#refund ] after the action **succeeded**
/// re-opens the token without any budget bound — refund only when the guarded
/// action certainly did not run.
public record SingleUse<T>(T value, Usage usage) {

    /// Recovery actions for a consumed token. `recycle` is for "the action ran
    /// and failed", `refund` for "the action never ran".
    public interface Usage {

        /// No-op usage for tokens decoded without single-use (`attempts = 0`).
        public static final Usage NONE = new Usage() {
            @Override
            public void recycle() {
            }

            @Override
            public void refund() {
            }
        };

        /// Re-enables one more decode within the `attempts` budget; the
        /// consumed attempt stays spent. Throws [TokenDepleted] when no
        /// attempts remain.
        void recycle();

        /// Cancels the consume as if it never happened: the attempt is
        /// refunded and the token un-blocked. Idempotent.
        void refund();
    }

    public void recycle() {
        usage.recycle();
    }

    public void refund() {
        usage.refund();
    }
}
