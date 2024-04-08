package sample.merge;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.web.client.RestOperations;
import sample.config.common.CustomAuthoritiesOpaqueTokenIntrospector;

import java.time.Duration;

public class AuthorizationResourceServerConfig {

	private final OAuth2ResourceServerProperties.Jwt jwtProperties;

	private final OAuth2ResourceServerProperties.Opaquetoken opaquetokenProperties;

	public AuthorizationResourceServerConfig(OAuth2ResourceServerProperties properties) {
		this.jwtProperties = properties.getJwt();
		this.opaquetokenProperties = properties.getOpaquetoken();
	}

//	@Bean
//	public JWKSource<SecurityContext> jwkSource() {
//		RSAKey rsaKey = Jwks.generateRsa();
//		JWKSet jwkSet = new JWKSet(rsaKey);
//		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
//	}

	//"http://localhost:9000/oauth2/jwks"
	@Bean
	public JwtDecoder jwtDecoder(RestTemplateBuilder builder,JWKSource<SecurityContext> jwkSource) {
		OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		RestOperations rest = builder
				.setConnectTimeout(Duration.ofSeconds(60))
				.setReadTimeout(Duration.ofSeconds(60))
				.build();
		return NimbusJwtDecoder.withJwkSetUri(this.jwtProperties.getJwkSetUri()).restOperations(rest).build();
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().issuer(this.jwtProperties.getIssuerUri()).build();
	}

	@Bean
	OpaqueTokenIntrospector introspect() {
		return new CustomAuthoritiesOpaqueTokenIntrospector(
				new SpringOpaqueTokenIntrospector(
						this.opaquetokenProperties.getIntrospectionUri(),
						this.opaquetokenProperties.getClientId(),
						this.opaquetokenProperties.getClientSecret()), jwtProperties);
	}
}
