package sample.userinfo;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import sample.common.Version;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


public class AuthUserDO implements UserDetails, CredentialsContainer, Serializable {

	@Serial
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

	private String id;


	private String username;


	private String password;


	private String authorities;


	private Boolean accountNonExpired;


	private Boolean accountNonLocked;


	private Boolean credentialsNonExpired;


	private Boolean enabled;


	private String tenantId;


	private Boolean deleteFlag;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return this.accountNonExpired;
	}

	@Override
	public boolean isAccountNonLocked() {
		return this.accountNonLocked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return this.credentialsNonExpired;
	}

	@Override
	public boolean isEnabled() {
		return this.enabled;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Set<SimpleGrantedAuthority> set = new HashSet<>();
		Set<String> role = StringUtils.commaDelimitedListToSet(this.authorities);
		role.forEach(x -> set.add(new SimpleGrantedAuthority(x)));
		return Collections.unmodifiableSet(set);
	}

	public AuthUserDO() {
	}

	public AuthUserDO(String id, String username, String password, String authorities, Boolean accountNonExpired, Boolean accountNonLocked, Boolean credentialsNonExpired, Boolean enabled, String tenantId, Boolean deleteFlag) {
		this.id = id;
		this.username = username;
		this.password = password;
		this.authorities = authorities;
		this.accountNonExpired = accountNonExpired;
		this.accountNonLocked = accountNonLocked;
		this.credentialsNonExpired = credentialsNonExpired;
		this.enabled = enabled;
		this.tenantId = tenantId;
		this.deleteFlag = deleteFlag;
	}

	public void eraseCredentials() {
		this.password = null;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Boolean getAccountNonExpired() {
		return accountNonExpired;
	}

	public void setAccountNonExpired(Boolean accountNonExpired) {
		this.accountNonExpired = accountNonExpired;
	}

	public Boolean getAccountNonLocked() {
		return accountNonLocked;
	}

	public void setAccountNonLocked(Boolean accountNonLocked) {
		this.accountNonLocked = accountNonLocked;
	}

	public Boolean getCredentialsNonExpired() {
		return credentialsNonExpired;
	}

	public void setCredentialsNonExpired(Boolean credentialsNonExpired) {
		this.credentialsNonExpired = credentialsNonExpired;
	}

	public Boolean getEnabled() {
		return enabled;
	}

	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}

	public String getTenantId() {
		return tenantId;
	}

	public void setTenantId(String tenantId) {
		this.tenantId = tenantId;
	}

	public Boolean getDeleteFlag() {
		return deleteFlag;
	}

	public void setDeleteFlag(Boolean deleteFlag) {
		this.deleteFlag = deleteFlag;
	}

	public void setAuthorities(String authorities) {
		this.authorities = authorities;
	}

	@Override
	public String toString() {
		return "AuthUserDO{" +
				"id='" + id + '\'' +
				", username='" + username + '\'' +
				", password='" + password + '\'' +
				", authorities='" + authorities + '\'' +
				", accountNonExpired=" + accountNonExpired +
				", accountNonLocked=" + accountNonLocked +
				", credentialsNonExpired=" + credentialsNonExpired +
				", enabled=" + enabled +
				", tenantId='" + tenantId + '\'' +
				", deleteFlag=" + deleteFlag +
				'}';
	}

	public static final String ID = "id";

	public static final String USERNAME  ="username";

	public static final String PASSWORD = "password";

	public static final String AUTHORITIES = "authorities";

	public static final String ACCOUNTNONEXPIRED = "accountNonExpired";

	public static final String ACCOUNTNONLOCKED = "accountNonLocked";

	public static final String CREDENTIALSNONEXPIRED = "credentialsNonExpired";

	public static final String ENABLED = "enabled";

	public static final String TENANTID = "tenantId";

	public static final String DELETEFLAG = "deleteFlag";
}
