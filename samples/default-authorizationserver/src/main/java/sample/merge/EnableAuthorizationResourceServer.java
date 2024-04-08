package sample.merge;

import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Import(AuthorizationResourceServerConfig.class)
@Target({ElementType.METHOD, ElementType.TYPE})
@Documented
public @interface EnableAuthorizationResourceServer {

	String value() default "";
}
