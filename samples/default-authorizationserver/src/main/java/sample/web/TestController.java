package sample.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sample.config.authorize.PreGroups;

import java.util.Collection;
import java.util.Map;

@RestController
@RequestMapping("/test")
public class TestController {

	@GetMapping("/ok")
	@PreGroups(hasGroups = {"rootVip1"})
	@PreAuthorize("hasAuthority('perms:root')")
//	@PreAuthorize("hasRole('perms:root')")
	public ResponseEntity<?> test(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal oAuth2AuthenticatedPrincipal) {
		Map<String, Object> attributes = oAuth2AuthenticatedPrincipal.getAttributes();
		System.out.println("attributes = " + attributes);

		Collection<? extends GrantedAuthority> authorities = oAuth2AuthenticatedPrincipal.getAuthorities();
		System.out.println("authorities = " + authorities);


		System.out.println("oAuth2AuthenticatedPrincipal.getAttributes() = " + oAuth2AuthenticatedPrincipal.getAttributes());
		return ResponseEntity.ok(oAuth2AuthenticatedPrincipal);
	}
}
