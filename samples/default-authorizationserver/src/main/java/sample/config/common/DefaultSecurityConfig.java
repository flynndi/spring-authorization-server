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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import sample.userinfo.CustomizeUserDetailImpl;

/**
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 1.1
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@EnableMethodSecurity
public class DefaultSecurityConfig {

	private final CustomizeUserDetailImpl customizeUserDetail;

	public DefaultSecurityConfig(CustomizeUserDetailImpl customizeUserDetail) {
		this.customizeUserDetail = customizeUserDetail;
	}

	// @formatter:off
	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//		http
//			.authorizeHttpRequests(authorize ->
//				authorize
//					.requestMatchers("/assets/**", "/login").permitAll()
//					.anyRequest().authenticated()
//			)
//			.userDetailsService(customizeUserDetail)
//			.formLogin(formLogin ->
//				formLogin
//					.loginPage("/login")
//			);
		http
				.authorizeHttpRequests(authorize ->
						authorize
								.anyRequest().authenticated()
				)
				.userDetailsService(customizeUserDetail)
				.formLogin(Customizer.withDefaults())
				// jwt和opaqueToken（不透明token）不能同时使用
//				.oauth2ResourceServer((oauth2ResourceServer) ->
//						oauth2ResourceServer.jwt(Customizer.withDefaults()))
				.oauth2ResourceServer((oauth2ResourceServer) ->
						oauth2ResourceServer.opaqueToken(Customizer.withDefaults()))
		;

		return http.build();
	}
	// @formatter:on

	@Bean
	PasswordEncoder passwordEncoder() {
		DelegatingPasswordEncoder delegatingPasswordEncoder = (DelegatingPasswordEncoder) PasswordEncoderFactories.createDelegatingPasswordEncoder();
		delegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(NoOpPasswordEncoder.getInstance());
		return delegatingPasswordEncoder;
	}

	// @formatter:off
//	@Bean
//	UserDetailsService users() {
//		UserDetails user = User.withDefaultPasswordEncoder()
//				.username("user1")
//				.password("password")
//				.roles("USER")
//				.build();
//		return new InMemoryUserDetailsManager(user);
//	}

	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

}
