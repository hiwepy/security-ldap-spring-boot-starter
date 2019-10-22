package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.ldap.property.SecurityActiveDirectoryLdapProperties;
import org.springframework.security.boot.ldap.property.SecurityLdapPopulatorProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityLdapProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityLdapProperties {

	public static final String PREFIX = "spring.security.ldap";

	/**
	 * Enable Security Ldap.
	 */
	private boolean enabled = false;

	@NestedConfigurationProperty
	private SecurityLdapPopulatorProperties populator = new SecurityLdapPopulatorProperties();
	@NestedConfigurationProperty
	private SecurityActiveDirectoryLdapProperties activeDirectory = new SecurityActiveDirectoryLdapProperties();
	
}
