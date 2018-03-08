package org.springframework.security.boot;

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = SecurityLdapProperties.PREFIX)
public class SecurityLdapProperties {
	
	public static final String PREFIX = "spring.security.ldap";
	
	/**
	 * Enable Security Ldap.
	 */
	private boolean enabled = false;
	
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
	
	/** cn=Manager,dc=gnetis,dc=com */
	private String userDn;
	
	private String password;
	
	/** The base suffix from which all operations should origin. If a base
	 * suffix is set, you will not have to (and, indeed, must not) specify the
	 * full distinguished names in any operations performed.  */
	private String base;
	
	private Map<String, Object> baseEnvironmentProperties;

	private boolean cacheEnvironmentProperties = true;
	
	/** FilterBasedLdapUserSearch */
	
	/** Context name to search in, relative to the base of the configured ContextSource. */
	private String searchBase = "";

	/**
	 * The filter expression used in the user search. This is an LDAP search filter (as
	 * defined in 'RFC 2254') with optional arguments. See the documentation for the
	 * <tt>search</tt> methods in {@link javax.naming.directory.DirContext DirContext} for
	 * more information.
	 *
	 * <p>
	 * In this case, the username is the only parameter.
	 * </p>
	 * Possible examples are:
	 * <ul>
	 * <li>(uid={0}) - this would search for a username match on the uid attribute.</li>
	 * </ul>
	 */
	private String searchFilter;
	
	/**The derefLinkFlag value as defined in SearchControls.. */
	private boolean derefLinkFlag;
	/**
	 * Specifies the attributes that will be returned as part of the search.
	 * <p>
	 * null indicates that all attributes will be returned. An empty array indicates no
	 * attributes are returned.
	 */
	public String[] returningAttrs = new String[]{};
	/** If true then searches the entire subtree as identified by context, if false (the default) then only searches the level identified by the context. */
	private boolean searchSubtree;
	/** The time to wait before the search fails (in milliseconds); the default is zero, meaning forever. */
	private int searchTimeLimit;
	public boolean isEnabled() {
		return enabled;
	}
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	public boolean isUseAuthenticationRequestCredentials() {
		return useAuthenticationRequestCredentials;
	}
	public void setUseAuthenticationRequestCredentials(boolean useAuthenticationRequestCredentials) {
		this.useAuthenticationRequestCredentials = useAuthenticationRequestCredentials;
	}
	public String[] getLdapUrls() {
		return ldapUrls;
	}
	public void setLdapUrls(String[] ldapUrls) {
		this.ldapUrls = ldapUrls;
	}
	public String[] getUrls() {
		return urls;
	}
	public void setUrls(String[] urls) {
		this.urls = urls;
	}
	public boolean isPooled() {
		return pooled;
	}
	public void setPooled(boolean pooled) {
		this.pooled = pooled;
	}
	public String getGroupSearchBase() {
		return groupSearchBase;
	}
	public void setGroupSearchBase(String groupSearchBase) {
		this.groupSearchBase = groupSearchBase;
	}
	public boolean isAnonymousReadOnly() {
		return anonymousReadOnly;
	}
	public void setAnonymousReadOnly(boolean anonymousReadOnly) {
		this.anonymousReadOnly = anonymousReadOnly;
	}
	public String getReferral() {
		return referral;
	}
	public void setReferral(String referral) {
		this.referral = referral;
	}
	public String getProviderUrl() {
		return providerUrl;
	}
	public void setProviderUrl(String providerUrl) {
		this.providerUrl = providerUrl;
	}
	public String getUserDn() {
		return userDn;
	}
	public void setUserDn(String userDn) {
		this.userDn = userDn;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getBase() {
		return base;
	}
	public void setBase(String base) {
		this.base = base;
	}
	public Map<String, Object> getBaseEnvironmentProperties() {
		return baseEnvironmentProperties;
	}
	public void setBaseEnvironmentProperties(Map<String, Object> baseEnvironmentProperties) {
		this.baseEnvironmentProperties = baseEnvironmentProperties;
	}
	public boolean isCacheEnvironmentProperties() {
		return cacheEnvironmentProperties;
	}
	public void setCacheEnvironmentProperties(boolean cacheEnvironmentProperties) {
		this.cacheEnvironmentProperties = cacheEnvironmentProperties;
	}
	public String getSearchBase() {
		return searchBase;
	}
	public void setSearchBase(String searchBase) {
		this.searchBase = searchBase;
	}
	public String getSearchFilter() {
		return searchFilter;
	}
	public void setSearchFilter(String searchFilter) {
		this.searchFilter = searchFilter;
	}
	public boolean isDerefLinkFlag() {
		return derefLinkFlag;
	}
	public void setDerefLinkFlag(boolean derefLinkFlag) {
		this.derefLinkFlag = derefLinkFlag;
	}
	public String[] getReturningAttrs() {
		return returningAttrs;
	}
	public void setReturningAttrs(String[] returningAttrs) {
		this.returningAttrs = returningAttrs;
	}
	public boolean isSearchSubtree() {
		return searchSubtree;
	}
	public void setSearchSubtree(boolean searchSubtree) {
		this.searchSubtree = searchSubtree;
	}
	public int getSearchTimeLimit() {
		return searchTimeLimit;
	}
	public void setSearchTimeLimit(int searchTimeLimit) {
		this.searchTimeLimit = searchTimeLimit;
	}
	
 
    
	
    

}
