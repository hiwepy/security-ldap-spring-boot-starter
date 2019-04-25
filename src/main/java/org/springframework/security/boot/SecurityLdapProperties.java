package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityCaptchaProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.ldap.property.SecurityActiveDirectoryLdapProperties;
import org.springframework.security.boot.ldap.property.SecurityLdapAuthcProperties;
import org.springframework.security.boot.ldap.property.SecurityLdapPopulatorProperties;

@ConfigurationProperties(prefix = SecurityLdapProperties.PREFIX)
public class SecurityLdapProperties {

	public static final String PREFIX = "spring.security.ldap";

	/**
	 * Enable Security Ldap.
	 */
	private boolean enabled = false;
	@NestedConfigurationProperty
	private SecurityLdapAuthcProperties authc = new SecurityLdapAuthcProperties();
	@NestedConfigurationProperty
	private SecurityCaptchaProperties captcha = new SecurityCaptchaProperties();
	@NestedConfigurationProperty
	private SecurityLdapPopulatorProperties populator = new SecurityLdapPopulatorProperties();
	@NestedConfigurationProperty
	private SecurityActiveDirectoryLdapProperties activeDirectory = new SecurityActiveDirectoryLdapProperties();
	@NestedConfigurationProperty
	private SecuritySessionMgtProperties sessionMgt = new SecuritySessionMgtProperties();
	
	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public SecurityLdapAuthcProperties getAuthc() {
		return authc;
	}

	public void setAuthc(SecurityLdapAuthcProperties authc) {
		this.authc = authc;
	}

	public SecurityCaptchaProperties getCaptcha() {
		return captcha;
	}

	public void setCaptcha(SecurityCaptchaProperties captcha) {
		this.captcha = captcha;
	}

	public SecurityLdapPopulatorProperties getPopulator() {
		return populator;
	}

	public void setPopulator(SecurityLdapPopulatorProperties populator) {
		this.populator = populator;
	}

	public SecurityActiveDirectoryLdapProperties getActiveDirectory() {
		return activeDirectory;
	}

	public void setActiveDirectory(SecurityActiveDirectoryLdapProperties activeDirectory) {
		this.activeDirectory = activeDirectory;
	}

	public SecuritySessionMgtProperties getSessionMgt() {
		return sessionMgt;
	}

	public void setSessionMgt(SecuritySessionMgtProperties sessionMgt) {
		this.sessionMgt = sessionMgt;
	}
	
}
