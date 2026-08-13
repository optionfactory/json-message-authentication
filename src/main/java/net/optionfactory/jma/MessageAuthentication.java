package net.optionfactory.jma;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.time.temporal.ChronoUnit;

@Documented
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface MessageAuthentication {

    public enum Mode {
        AUTHENTICATED, AUTHENTICATED_ENCRYPTED;
    }

    Mode mode() default Mode.AUTHENTICATED_ENCRYPTED;

    long validity() default 6;

    ChronoUnit unit() default ChronoUnit.HOURS;
}
