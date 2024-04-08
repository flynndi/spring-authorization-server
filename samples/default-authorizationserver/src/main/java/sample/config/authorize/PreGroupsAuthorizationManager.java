package sample.config.authorize;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

public final class PreGroupsAuthorizationManager implements AuthorizationManager<MethodInvocation> {

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation object) {
		DefaultOAuth2AuthenticatedPrincipal oAuth2AuthenticatedPrincipal = (DefaultOAuth2AuthenticatedPrincipal) authentication.get().getPrincipal();

		PreGroups preGroups = object.getMethod().getAnnotation(PreGroups.class);
		if (Objects.nonNull(preGroups)) {
			List<String> list = Arrays.asList(preGroups.hasGroups());
			Object groupsObject = oAuth2AuthenticatedPrincipal.getAttributes().get("groups");
			List<String> groups = this.castList(groupsObject, String.class);
			if (!list.isEmpty()) {
				for (String s : list) {
					if (groups.contains(s)) {
						return new AuthorizationDecision(true);
					}
				}
			}
		}
		return new AuthorizationDecision(false);
    }

	private <T> List<T> castList(Object obj, Class<T> clazz) {
		List<T> result = new ArrayList<T>();
		if(obj instanceof List<?>)
		{
			for (Object o : (List<?>) obj)
			{
				result.add(clazz.cast(o));
			}
			return result;
		}
		return null;
	}
}
