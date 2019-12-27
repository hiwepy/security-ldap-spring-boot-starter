/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.ldap.property;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;

public class SecurityActiveDirectoryLdapProperties {

	/**
	 * Specialized LDAP authentication provider which uses Active Directory
	 * configuration conventions.
	 */
	private boolean enabled = false;
	private String domain;
	private String rootDn;
	private String url;
	private boolean convertSubErrorCodesToExceptions;
	private String searchFilter = "(&(objectClass=user)(userPrincipalName={0}))";
	private Map<String, Object> environment = new HashMap<String, Object>();

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	public String getRootDn() {
		return rootDn;
	}

	public void setRootDn(String rootDn) {
		this.rootDn = rootDn;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public boolean isConvertSubErrorCodesToExceptions() {
		return convertSubErrorCodesToExceptions;
	}

	/**
	 * By default, a failed authentication (LDAP error 49) will result in a
	 * {@code BadCredentialsException}.
	 * <p>
	 * If this property is set to {@code true}, the exception message from a failed
	 * bind attempt will be parsed for the AD-specific error code and a
	 * {@link CredentialsExpiredException}, {@link DisabledException},
	 * {@link AccountExpiredException} or {@link LockedException} will be thrown for
	 * the corresponding codes. All other codes will result in the default
	 * {@code BadCredentialsException}.
	 *
	 * @param convertSubErrorCodesToExceptions {@code true} to raise an exception
	 *                                         based on the AD error code.
	 */
	public void setConvertSubErrorCodesToExceptions(boolean convertSubErrorCodesToExceptions) {
		this.convertSubErrorCodesToExceptions = convertSubErrorCodesToExceptions;
	}

	public String getSearchFilter() {
		return searchFilter;
	}

	/**
	 * The LDAP filter string to search for the user being authenticated.
	 * Occurrences of {0} are replaced with the {@code username@domain}. Occurrences
	 * of {1} are replaced with the {@code username} only.
	 * <p>
	 * Defaults to: {@code (&(objectClass=user)(userPrincipalName= 0}))}
	 * </p>
	 *
	 * @param searchFilter the filter string
	 *
	 */
	public void setSearchFilter(String searchFilter) {
		this.searchFilter = searchFilter;
	}

	public Map<String, Object> getEnvironment() {
		return environment;
	}

	/**
	 * Allows a custom environment properties to be used to create initial LDAP
	 * context.
	 *
	 * @param environment the additional environment parameters to use when creating
	 *                    the LDAP Context
	 */
	public void setEnvironment(Map<String, Object> environment) {
		this.environment = environment;
	}

}
