package net.optionfactory.jma;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.time.temporal.ChronoUnit;

/// Authenticates and optionally encrypts the annotated element during Jackson
/// serialization/deserialization.
///
/// When placed on a `FIELD` or `PARAMETER`, works for any value type
/// (strings, objects, enums, collections, etc.).
///
/// When placed on a `TYPE`, only **bean and record types** are supported.
/// Enums, arrays, collections, maps, and primitive wrappers are not handled
/// at the class level — annotate the field instead in those cases.
///
/// `AUTHENTICATED` mode provides integrity but **not confidentiality**: the
/// plaintext is embedded in the serialized output. Use `AUTHENTICATED_ENCRYPTED`
/// when the value must not be readable.
///
/// Placing the annotation on both a field and its type applies both layers
/// independently (the value is processed twice). This is functional,
/// serialization wraps the inner layer's output, and deserialization peels
/// them back in reverse order, but redundant. Prefer annotating only one.
///
/// May be used as a **meta-annotation**: place it on your own annotation to
/// create a bundle with fixed defaults (e.g. `@ResetToken`). That bundle
/// annotation must be declared `@Retention(RUNTIME)` and its `@Target` should
/// mirror this one — `FIELD`, `PARAMETER`, plus `TYPE` for type-level bundles.
/// In particular `PARAMETER` is required for the bundle to be recognized on
/// **record components**, since records deserialize through the constructor
/// parameter. A direct `@MessageAuthentication` takes precedence over a
/// meta-annotated one.
@Documented
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.TYPE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface MessageAuthentication {

    public enum Mode {
        AUTHENTICATED, AUTHENTICATED_ENCRYPTED;
    }

    /// @return the authentication/encryption mode.
    Mode mode() default Mode.AUTHENTICATED_ENCRYPTED;

    /// @return how long the token remains valid. Embedded in the token and
    /// MAC-protected at serialization time, so it is committed at issuance and
    /// cannot be reinterpreted at verification time.
    long validity() default 6;

    /// @return the time unit for [ validity() ].
    ChronoUnit unit() default ChronoUnit.HOURS;

    /// @return the single-use policy: `0` (default) disables single-use entirely
    /// (the token is freely reusable, matching pre-3.0 behavior); `1` enables
    /// strict single-use (one decode only); `N > 1` allows up to `N` decodes.
    int attempts() default 0;
}
