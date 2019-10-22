/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecurityCaptchaProperties;
import org.springframework.security.boot.ldap.authentication.AuthoritiesMapperPolicy;
import org.springframework.security.boot.ldap.authentication.DirContextPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(SecurityLdapAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityLdapAuthcProperties extends SecurityAuthcProperties {

	public static final String PREFIX = "spring.security.ldap.authc";
	
	private String loginUrlPatterns = "/login/ldap";;
	/** 系统主页：登录成功后跳转路径 */
	private String successUrl = "/index";;
	/** 异常页面：认证失败时的跳转路径 */
	private String failureUrl = "/error";
	
	/** the username parameter name. Defaults to "username". */
	private String usernameParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY;
	/** the password parameter name. Defaults to "password". */
	private String passwordParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY;
	private String targetUrlParameter = "target";
	private boolean useAuthenticationRequestCredentials = true;

	private String[] ldapUrls;

	/** The url of the LDAP server. */
	private String[] urls;

	private boolean pooled = false;

	private String groupSearchBase = "";

	private boolean anonymousReadOnly = false;

	private String referral = null;

	/** ldap://192.168.0.1:389/dc=gnetis,dc=com */
	private String providerUrl;
	private boolean postOnly = true;
	/** cn=Manager,dc=gnetis,dc=com */
	private String userDn;

	private String password;

	/**
	 * The base suffix from which all operations should origin. If a base suffix is
	 * set, you will not have to (and, indeed, must not) specify the full
	 * distinguished names in any operations performed.
	 */
	private String base;

	private Map<String, Object> baseEnvironmentProperties;

	private boolean cacheEnvironmentProperties = true;
	private boolean hideUserNotFoundExceptions = true;
	/** FilterBasedLdapUserSearch */

	/**
	 * Context name to search in, relative to the base of the configured
	 * ContextSource.
	 */
	private String searchBase = "";

	/**
	 * The filter expression used in the user search. This is an LDAP search filter
	 * (as defined in 'RFC 2254') with optional arguments. See the documentation for
	 * the <tt>search</tt> methods in {@link javax.naming.directory.DirContext
	 * DirContext} for more information.
	 *
	 * <p>
	 * In this case, the username is the only parameter.
	 * </p>
	 * Possible examples are:
	 * <ul>
	 * <li>(uid={0}) - this would search for a username match on the uid
	 * attribute.</li>
	 * </ul>
	 */
	private String searchFilter;

	/** The derefLinkFlag value as defined in SearchControls.. */
	private boolean derefLinkFlag;
	/**
	 * Specifies the attributes that will be returned as part of the search.
	 * <p>
	 * null indicates that all attributes will be returned. An empty array indicates
	 * no attributes are returned.
	 */
	public String[] returningAttrs = new String[] {};
	/**
	 * If true then searches the entire subtree as identified by context, if false
	 * (the default) then only searches the level identified by the context.
	 */
	private boolean searchSubtree;
	/**
	 * The time to wait before the search fails (in milliseconds); the default is
	 * zero, meaning forever.
	 */
	private int searchTimeLimit;

	private DirContextPolicy dirContextPolicy = DirContextPolicy.SIMPLE;
	private AuthoritiesMapperPolicy authoritiesMapperPolicy = AuthoritiesMapperPolicy.NONE;
	private boolean useReferer = false;
	private boolean useForward = false; 

	@NestedConfigurationProperty
	private SecurityCaptchaProperties captcha = new SecurityCaptchaProperties();
	
}
