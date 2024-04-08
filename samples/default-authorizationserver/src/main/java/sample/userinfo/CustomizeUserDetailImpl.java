package sample.userinfo;

import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import sample.common.BeanContainer;

@Service
public class CustomizeUserDetailImpl implements UserDetailsService {


	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		String sql =
    			"""
				SELECT
					*\s
				FROM
					auth_user\s
				WHERE
					username = ?
				""";
		JdbcTemplate jdbcTemplate = BeanContainer.getBean(JdbcTemplate.class);
		return jdbcTemplate.queryForObject(sql, new BeanPropertyRowMapper<>(AuthUserDO.class), username);
	}
}
