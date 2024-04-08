package sample.config.common;

import org.springframework.boot.web.embedded.undertow.UndertowDeploymentInfoCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.Executors;

@Configuration(proxyBeanMethods = false)
public class ServerPool {

//	@Bean
//	TomcatProtocolHandlerCustomizer<?> threadExecutorCustomizer() {
//		return protocolHandler -> protocolHandler.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
//	}

	@Bean
	public UndertowDeploymentInfoCustomizer threadExecutorCustomizer() {
		return protocolHandler -> protocolHandler.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
	}
}
