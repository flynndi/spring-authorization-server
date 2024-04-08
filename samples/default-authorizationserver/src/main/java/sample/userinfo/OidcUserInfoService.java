package sample.userinfo;

import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;
import sample.common.BeanContainer;

import java.util.*;

@Service
public class OidcUserInfoService {

	private final UserInfoRepository userInfoRepository = new UserInfoRepository();

	public OidcUserInfo loadUser(String username) {
		return new OidcUserInfo(this.userInfoRepository.findByUsername(username));
	}

	static class UserInfoRepository {

		public UserInfoRepository() {
		}

		public Map<String, Object> findByUsername(String username) {
			JdbcTemplate jdbcTemplate = BeanContainer.getBean(JdbcTemplate.class);
			AuthUserDO authUserDO = jdbcTemplate.queryForObject("SELECT * FROM auth_user WHERE username = ?", new BeanPropertyRowMapper<>(AuthUserDO.class), username);
			if (Objects.isNull(authUserDO)) {
				return null;
			} else {
				return this.createUser(authUserDO);
			}
		}

		private Map<String, Object> createUser(AuthUserDO authUserDO) {
			JdbcTemplate jdbcTemplate = BeanContainer.getBean(JdbcTemplate.class);
			String roleSql =
					"""
					SELECT
						t3.role_name\s
					FROM
						auth_user t1
						LEFT JOIN user_role t2 ON t1.ID = t2.user_id
						LEFT JOIN auth_role t3 ON t2.role_id = t3.ID\s
					WHERE
						t1.delete_flag = 'f'\s
						AND t2.delete_flag = 'f'\s
						AND t3.delete_flag = 'f'\s
						AND t1.ID = ?
					""";
			List<String> role = jdbcTemplate.queryForList(roleSql, String.class, authUserDO.getId());
			String permsSql =
     				"""
					SELECT DISTINCT ON
						( t5.ID ) t5.perms\s
                 	FROM
                     	auth_user t1
                     	LEFT JOIN user_role t2 ON t1.ID = t2.user_id
                     	LEFT JOIN auth_role t3 ON t2.role_id = t3.ID
                     	LEFT JOIN role_menu t4 ON t4.role_id = t3.ID
                     	LEFT JOIN auth_menu t5 ON t5.ID = t4.menu_id\s
                 	WHERE
                         t1.delete_flag = 'f'\s
                         AND t2.delete_flag = 'f'\s
                         AND t3.delete_flag = 'f'\s
                         AND t4.delete_flag = 'f'\s
                         AND t5.delete_flag = 'f'\s
                         AND t1.ID = ?
					""";
			List<String> permsList = jdbcTemplate.queryForList(permsSql, String.class, authUserDO.getId());
			Map<String, Object> claims = OidcUserInfo.builder()
					.subject(authUserDO.getUsername())
					.name("First Last")
					.givenName("First")
					.familyName("Last")
					.middleName("Middle")
					.nickname("User")
					.preferredUsername(authUserDO.getUsername())
					.profile("https://example.com/" + authUserDO.getUsername())
					.picture("https://example.com/" + authUserDO.getUsername() + ".jpg")
					.website("https://example.com")
					.email(authUserDO.getUsername() + "@example.com")
					.emailVerified(true)
					.gender("female")
					.birthdate("1970-01-01")
					.zoneinfo("Europe/Paris")
					.locale("en-US")
					.phoneNumber("+1 (604) 555-1234;ext=5678")
					.phoneNumberVerified(false)
					.claim("address", Collections.singletonMap("formatted", "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"))
					.updatedAt("1970-01-01T00:00:00Z")
					.build()
					.getClaims();
			Map<String, Object> map = new LinkedHashMap<>(claims);
			map.put("groups", role);
			map.put("perms", permsList);
			return map;
		}
	}
}
