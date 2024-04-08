package sample.config.common;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class CustomAuthoritiesOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

	private static final String DEFAULT_OIDC_USER_INFO_ENDPOINT_URI = "/userinfo";

	private static final String GROUPS = "groups";

	private final OpaqueTokenIntrospector delegate;

	private final OAuth2ResourceServerProperties.Jwt jwtProperties;

	public CustomAuthoritiesOpaqueTokenIntrospector(OpaqueTokenIntrospector delegate, OAuth2ResourceServerProperties.Jwt jwtProperties) {
		this.delegate = delegate;
		this.jwtProperties = jwtProperties;
	}


	@Override
	public OAuth2AuthenticatedPrincipal introspect(String token) {
		OAuth2AuthenticatedPrincipal principal = this.delegate.introspect(token);

		Consumer<HttpHeaders> headersConsumer = httpHeaders -> httpHeaders.setBearerAuth(token);
		final WebClient webClient = WebClient.builder().baseUrl(this.jwtProperties.getIssuerUri()).build();
		UserinfoResponse userinfo = webClient
				.get()
				.uri(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI)
				.headers(headersConsumer)
				.retrieve()
				.bodyToMono(UserinfoResponse.class)
				.block();

        if (Objects.isNull(userinfo)) {
			throw new InvalidBearerTokenException("userinfo does not exist");
		}

		Map<String, Object> attributes = principal.getAttributes();
		Map<String, Object> map = new LinkedHashMap<>(attributes);
		map.put(GROUPS, userinfo.getGroups());

		return new DefaultOAuth2AuthenticatedPrincipal(
				principal.getName(), map, userinfo.getPerms().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
	}

	private static class UserinfoResponse {

		private String sub;

		private List<String> perms = Collections.emptyList();

		private List<String> groups = Collections.emptyList();

		public String getSub() {
			return sub;
		}

		public void setSub(String sub) {
			this.sub = sub;
		}

		public List<String> getPerms() {
			return perms;
		}

		public void setPerms(List<String> perms) {
			this.perms = perms;
		}

		public List<String> getGroups() {
			return groups;
		}

		public void setGroups(List<String> groups) {
			this.groups = groups;
		}

		@Override
		public String toString() {
			return "UserinfoResponse{" +
					"sub='" + sub + '\'' +
					", perms=" + perms +
					", groups=" + groups +
					'}';
		}
	}
}
