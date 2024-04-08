package sample.config.authorize;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.Pointcuts;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.core.Ordered;
import org.springframework.core.log.LogMessage;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;

import java.lang.annotation.Annotation;
import java.util.function.Supplier;

public class CustomizingAuthorizationManagerBeforeMethodInterceptor implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	private final Log logger = LogFactory.getLog(this.getClass());

	private final Pointcut pointcut;

	private final AuthorizationManager<MethodInvocation> authorizationManager;

	private Supplier<Authentication> authentication = getAuthentication(
			SecurityContextHolder.getContextHolderStrategy());

	private int order = AuthorizationInterceptorsOrder.LAST.getOrder();

	private AuthorizationEventPublisher eventPublisher = CustomizingAuthorizationManagerBeforeMethodInterceptor::noPublish;


	public CustomizingAuthorizationManagerBeforeMethodInterceptor(Pointcut pointcut,
			AuthorizationManager<MethodInvocation> authorizationManager) {
		Assert.notNull(pointcut, "pointcut cannot be null");
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.pointcut = pointcut;
		this.authorizationManager = authorizationManager;
	}

	public static CustomizingAuthorizationManagerBeforeMethodInterceptor preGroups() {
		return preGroups(new PreGroupsAuthorizationManager());
	}


	public static CustomizingAuthorizationManagerBeforeMethodInterceptor preGroups(
			PreGroupsAuthorizationManager authorizationManager) {
		CustomizingAuthorizationManagerBeforeMethodInterceptor interceptor = new CustomizingAuthorizationManagerBeforeMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(PreGroups.class), authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder());
		return interceptor;
	}

	@Override
	public Object invoke(MethodInvocation invocation) throws Throwable {
		attemptAuthorization(invocation);
		return invocation.proceed();
	}

	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

	@Override
	public Advice getAdvice() {
		return this;
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	public void setAuthorizationEventPublisher(AuthorizationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "eventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
	}

	@Override
	public boolean isPerInstance() {
		return true;
	}

	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.authentication = getAuthentication(securityContextHolderStrategy);
	}

	private void attemptAuthorization(MethodInvocation mi) {
		this.logger.debug(LogMessage.of(() -> "Authorizing method invocation " + mi));
		AuthorizationDecision decision = this.authorizationManager.check(this.authentication, mi);
		this.eventPublisher.publishAuthorizationEvent(this.authentication, mi, decision);
		if (decision != null && !decision.isGranted()) {
			this.logger.debug(LogMessage.of(() -> "Failed to authorize " + mi + " with authorization manager "
					+ this.authorizationManager + " and decision " + decision));
			throw new AccessDeniedException("Access Denied");
		}
		this.logger.debug(LogMessage.of(() -> "Authorized method invocation " + mi));
	}

	private Supplier<Authentication> getAuthentication(SecurityContextHolderStrategy strategy) {
		return () -> {
			Authentication authentication = strategy.getContext().getAuthentication();
			if (authentication == null) {
				throw new AuthenticationCredentialsNotFoundException(
						"An Authentication object was not found in the SecurityContext");
			}
			return authentication;
		};
	}

	private static <T> void noPublish(Supplier<Authentication> authentication, T object, AuthorizationDecision decision) {

	}

	static class AuthorizationMethodPointcuts {
		static Pointcut forAllAnnotations() {
			return forAnnotations(PreGroups.class);
		}

		@SafeVarargs
		static Pointcut forAnnotations(Class<? extends Annotation>... annotations) {
			ComposablePointcut pointcut = null;
			for (Class<? extends Annotation> annotation : annotations) {
				if (pointcut == null) {
					pointcut = new ComposablePointcut(classOrMethod(annotation));
				}
				else {
					pointcut.union(classOrMethod(annotation));
				}
			}
			return pointcut;
		}

		private static Pointcut classOrMethod(Class<? extends Annotation> annotation) {
			return Pointcuts.union(new AnnotationMatchingPointcut(null, annotation, true),
					new AnnotationMatchingPointcut(annotation, true));
		}

		private AuthorizationMethodPointcuts() {

		}
	}
}
