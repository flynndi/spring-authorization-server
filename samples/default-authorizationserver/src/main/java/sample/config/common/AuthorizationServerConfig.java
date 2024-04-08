/*
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config.common;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.List;

/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Steve Riesenberg
 * @since 1.1
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

		// 两种方式都可以 如果要开启默认配置的 userinfo等公共端点 必须http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
				.oidc(Customizer.withDefaults())
				.oidc(oidc -> oidc.clientRegistrationEndpoint(Customizer.withDefaults()));
//				.tokenIntrospectionEndpoint(Customizer.withDefaults());

		http
				// Redirect to the login page when not authenticated from the
				// authorization endpoint
				.exceptionHandling((exceptions) -> exceptions
						.defaultAuthenticationEntryPointFor(
								new LoginUrlAuthenticationEntryPoint("/login"),
								new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
						)
				)
				// Accept access tokens for User Info and/or Client Registration
				.oauth2ResourceServer((resourceServer) -> resourceServer
						.jwt(Customizer.withDefaults()));


		// 第二种方式，自定义userInfoMapper时使用
//		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
//				new OAuth2AuthorizationServerConfigurer();
//		RequestMatcher endpointsMatcher = authorizationServerConfigurer
//				.getEndpointsMatcher();
//
//		Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context) -> { // <2>
//			OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
//			JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
//
//			return new OidcUserInfo(principal.getToken().getClaims());
//		};
//
//		authorizationServerConfigurer
//				.oidc((oidc) -> oidc
//						.userInfoEndpoint((userInfo) -> userInfo
//								.userInfoMapper(userInfoMapper) // <3>
//						)
//				);
//
//		http
//				.securityMatcher(endpointsMatcher)
//				.authorizeHttpRequests((authorize) -> authorize
//						.anyRequest().authenticated()
//				)
//				.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
//				.oauth2ResourceServer(resourceServer -> resourceServer
//						.jwt(Customizer.withDefaults()) // <4>
//				)
//				.exceptionHandling((exceptions) -> exceptions
//						.defaultAuthenticationEntryPointFor(
//								new LoginUrlAuthenticationEntryPoint("/login"),
//								new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//						)
//				)
//				.apply(authorizationServerConfigurer);
		return http.build();
	}

	// @formatter:off
	@Bean
	public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
//		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//				.clientId("messaging-client")
//				.clientSecret("{noop}secret")
//				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
//				.redirectUri("http://127.0.0.1:8080/authorized")
//				.scope(OidcScopes.OPENID)
//				.scope(OidcScopes.PROFILE)
//				.scope("message.read")
//				.scope("message.write")
//				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//				.build();

//		RegisteredClient deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
//				.clientId("device-messaging-client")
//				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
//				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
//				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//				.scope("message.read")
//				.scope("message.write")
//				.build();

		// Save registered client's in db as if in-memory
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
//		registeredClientRepository.save(registeredClient);
//		registeredClientRepository.save(deviceClient);

		return registeredClientRepository;
	}
	// @formatter:on

//	@Bean
//	public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
//		JdbcOAuth2AuthorizationService authorizationService =
//				new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
//		JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper =
//				new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
//		JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper oAuth2AuthorizationParametersMapper =
//				new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();
//		ObjectMapper objectMapper = new ObjectMapper();
//		ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
//		List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
//		objectMapper.registerModules(securityModules);
//		objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
//		objectMapper.registerModule(new CustomizeJackson2Module());
////		objectMapper.addMixIn(AuthUserDO.class, AuthUserDOMixin.class);
//		rowMapper.setObjectMapper(objectMapper);
//		oAuth2AuthorizationParametersMapper.setObjectMapper(objectMapper);
//		authorizationService.setAuthorizationRowMapper(rowMapper);
//		authorizationService.setAuthorizationParametersMapper(oAuth2AuthorizationParametersMapper);
//		return authorizationService;
//	}

	// 以下代码在 AuthorizationResourceServerConfig 中
//	@Bean
//	public JWKSource<SecurityContext> jwkSource() {
//		RSAKey rsaKey = Jwks.generateRsa();
//		JWKSet jwkSet = new JWKSet(rsaKey);
//		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
//	}

//	@Bean
//	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//	}

//	@Bean
//	public AuthorizationServerSettings authorizationServerSettings() {
//		return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
//	}

//	@Bean
	public EmbeddedDatabase embeddedDatabase() {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
		// @formatter:on
	}

}
