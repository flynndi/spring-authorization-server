package sample.config.authorize;

import org.springframework.aop.Advisor;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;

@Configuration(proxyBeanMethods = false)
public class CustomizingAuthorizationConfig {


	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	Advisor preGroupsAuthorizeAuthorizationMethodInterceptor() {
		return CustomizingAuthorizationManagerBeforeMethodInterceptor.preGroups();
	}


}
