package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.AuthenticationSource;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.DigestMd5DirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.ExternalTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyAuthoritiesMapper;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.ldap.authentication.AuthoritiesMapperPolicy;
import org.springframework.security.boot.ldap.authentication.DirContextPolicy;
import org.springframework.security.boot.ldap.authentication.LdapAuthenticationFailureHandler;
import org.springframework.security.boot.ldap.authentication.LdapAuthenticationSuccessHandler;
import org.springframework.security.boot.ldap.authentication.LdapUsernamePasswordAuthenticationToken;
import org.springframework.security.boot.ldap.property.SecurityActiveDirectoryLdapProperties;
import org.springframework.security.boot.ldap.property.SecurityLdapAuthcProperties;
import org.springframework.security.boot.ldap.property.SecurityLdapPopulatorProperties;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator;
import org.springframework.security.ldap.authentication.SpringSecurityAuthenticationSource;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityLdapProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityLdapProperties.class, SecurityBizProperties.class })
public class SecurityLdapAutoConfiguration {

	public LdapContextSource ldapContextSource(SecurityLdapAuthcProperties authcProperties) {
		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
				authcProperties.getProviderUrl());
		contextSource.assembleProviderUrlString(authcProperties.getLdapUrls());
		/*
		 * contextSource.setAnonymousReadOnly(anonymousReadOnly);
		 * contextSource.setAuthenticationSource(authenticationSource);
		 * contextSource.setAuthenticationStrategy(authenticationStrategy);
		 * contextSource.setBase(base);
		 * contextSource.setBaseEnvironmentProperties(baseEnvironmentProperties);
		 * contextSource.setCacheEnvironmentProperties(cacheEnvironmentProperties);
		 * contextSource.setPassword(password); contextSource.setPooled(pooled);
		 * contextSource.setReferral(referral);
		 */
		return contextSource;
	}

	@Bean
	public DirContextAuthenticationStrategy authenticationStrategy(SecurityLdapAuthcProperties authcProperties) {
		if (DirContextPolicy.DEFAULT_TLS.equals(authcProperties.getDirContextPolicy())) {
			return new DefaultTlsDirContextAuthenticationStrategy();
		} else if (DirContextPolicy.EXTERNAL_TLS.equals(authcProperties.getDirContextPolicy())) {
			return new ExternalTlsDirContextAuthenticationStrategy();
		} else if (DirContextPolicy.DIGEST_MD5.equals(authcProperties.getDirContextPolicy())) {
			return new DigestMd5DirContextAuthenticationStrategy();
		} else {
			return new SimpleDirContextAuthenticationStrategy();
		}
	}

	@Bean
	public AuthenticationSource authenticationSource() {
		return new SpringSecurityAuthenticationSource();
	}

	@Bean
	@ConditionalOnMissingBean
	public BaseLdapPathContextSource contextSource(
			SecurityLdapAuthcProperties authcProperties,
			DirContextAuthenticationStrategy authenticationStrategy,
			AuthenticationSource authenticationSource) {

		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
				authcProperties.getProviderUrl());

		contextSource.assembleProviderUrlString(authcProperties.getLdapUrls());
		contextSource.setAnonymousReadOnly(authcProperties.isAnonymousReadOnly());
		contextSource.setAuthenticationSource(authenticationSource);
		contextSource.setAuthenticationStrategy(authenticationStrategy);
		contextSource.setBase(authcProperties.getBase());
		contextSource.setBaseEnvironmentProperties(authcProperties.getBaseEnvironmentProperties());
		contextSource.setCacheEnvironmentProperties(authcProperties.isCacheEnvironmentProperties());
		contextSource.setPassword(authcProperties.getPassword());
		contextSource.setPooled(authcProperties.isPooled());
		contextSource.setReferral(authcProperties.getReferral());
		contextSource.setUrls(authcProperties.getUrls());
		contextSource.setUserDn(authcProperties.getUserDn());

		return contextSource;
	}

	@Bean
	@ConditionalOnMissingBean
	public LdapUserSearch userSearch(SecurityLdapAuthcProperties authcProperties, BaseLdapPathContextSource contextSource) {

		FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(authcProperties.getSearchBase(),
				authcProperties.getSearchFilter(), contextSource);

		userSearch.setDerefLinkFlag(authcProperties.isDerefLinkFlag());
		userSearch.setReturningAttributes(authcProperties.getReturningAttrs());
		userSearch.setSearchSubtree(authcProperties.isSearchSubtree());
		userSearch.setSearchTimeLimit(authcProperties.getSearchTimeLimit());

		return userSearch;
	}

	@Bean
	@ConditionalOnMissingBean
	public UserDetailsService userDetailsService(LdapUserSearch userSearch,
			LdapAuthoritiesPopulator authoritiesPopulator) {
		return new LdapUserDetailsService(userSearch, authoritiesPopulator);
	}
	
	@Bean
	@ConditionalOnMissingBean
	public UserDetailsContextMapper userDetailsContextMapper() {
		return new LdapUserDetailsMapper();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public GrantedAuthoritiesMapper authoritiesMapper(SecurityLdapAuthcProperties authcProperties,RoleHierarchy roleHierarchy) {
		if (AuthoritiesMapperPolicy.ROLE_HIERARCHY.equals(authcProperties.getAuthoritiesMapperPolicy())) {
			return new RoleHierarchyAuthoritiesMapper(roleHierarchy);
		} else if (AuthoritiesMapperPolicy.SIMPLE.equals(authcProperties.getAuthoritiesMapperPolicy())) {
			return new SimpleAuthorityMapper();
		} else {
			return new NullAuthoritiesMapper();
		}
	}

	@Bean
	@ConditionalOnMissingBean
	public AbstractLdapAuthenticator ldapAuthenticator(BaseLdapPathContextSource ldapPathContextSource) {
		return new PasswordComparisonAuthenticator(ldapPathContextSource);
	}

	@Bean
	public LdapAuthoritiesPopulator ldapAuthoritiesPopulator(
			SecurityLdapProperties ldapProperties,
			SecurityLdapAuthcProperties authcProperties,
			BaseLdapPathContextSource contextSource) {

		SecurityLdapPopulatorProperties populatorProperties = ldapProperties.getPopulator();
		
		DefaultLdapAuthoritiesPopulator authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(contextSource,
				authcProperties.getGroupSearchBase());
		authoritiesPopulator.setConvertToUpperCase(populatorProperties.isConvertToUpperCase());
		authoritiesPopulator.setDefaultRole(populatorProperties.getDefaultRole());
		authoritiesPopulator.setGroupRoleAttribute(populatorProperties.getGroupRoleAttribute());
		authoritiesPopulator.setGroupSearchFilter(populatorProperties.getGroupSearchFilter());
		authoritiesPopulator.setIgnorePartialResultException(populatorProperties.isIgnorePartialResultException());
		authoritiesPopulator.setRolePrefix(populatorProperties.getRolePrefix());
		authoritiesPopulator.setSearchSubtree(populatorProperties.isSearchSubtree());
		
		return authoritiesPopulator;
	}

	@Bean
	public AbstractLdapAuthenticationProvider ldapAuthenticationProvider(
			SecurityLdapProperties ldapProperties,
			SecurityLdapAuthcProperties authcProperties,
			GrantedAuthoritiesMapper authoritiesMapper,
			LdapAuthenticator ldapAuthenticator,
			LdapAuthoritiesPopulator ldapAuthoritiesPopulator, 
			MessageSource messageSource, 
			UserDetailsContextMapper userDetailsContextMapper) throws Exception {

		SecurityActiveDirectoryLdapProperties adLdapProperties = ldapProperties.getActiveDirectory();
		if (adLdapProperties.isEnabled()) {

			ActiveDirectoryLdapAuthenticationProvider authenticationProvider = new ActiveDirectoryLdapAuthenticationProvider(
					adLdapProperties.getDomain(), adLdapProperties.getUrl(), adLdapProperties.getRootDn());

			authenticationProvider.setAuthoritiesMapper(authoritiesMapper);
			authenticationProvider.setContextEnvironmentProperties(adLdapProperties.getEnvironment());
			authenticationProvider.setConvertSubErrorCodesToExceptions(adLdapProperties.isConvertSubErrorCodesToExceptions());
			authenticationProvider.setMessageSource(messageSource);
			authenticationProvider.setSearchFilter(authcProperties.getSearchFilter());
			authenticationProvider.setUseAuthenticationRequestCredentials(authcProperties.isUseAuthenticationRequestCredentials());
			authenticationProvider.setUserDetailsContextMapper(userDetailsContextMapper);
			return authenticationProvider;
		}

		LdapAuthenticationProvider authenticationProvider = new LdapAuthenticationProvider(ldapAuthenticator,
				ldapAuthoritiesPopulator) {
			public boolean supports(Class<?> authentication) {
				return LdapUsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
			}
		};

		authenticationProvider.setAuthoritiesMapper(authoritiesMapper);
		authenticationProvider.setHideUserNotFoundExceptions(authcProperties.isHideUserNotFoundExceptions());
		authenticationProvider.setMessageSource(messageSource);
		authenticationProvider.setUseAuthenticationRequestCredentials(authcProperties.isUseAuthenticationRequestCredentials());
		authenticationProvider.setUserDetailsContextMapper(userDetailsContextMapper);

		return authenticationProvider;
	}

	@Bean
	public LdapAuthenticationSuccessHandler ldapAuthenticationSuccessHandler(
			SecurityLdapProperties ldapProperties,
			SecurityLdapAuthcProperties authcProperties,
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Qualifier("upcRedirectStrategy") RedirectStrategy redirectStrategy, 
			@Qualifier("upcRequestCache") RequestCache requestCache) {
		LdapAuthenticationSuccessHandler successHandler = new LdapAuthenticationSuccessHandler(
				authenticationListeners, authcProperties.getSuccessUrl());
		successHandler.setRedirectStrategy(redirectStrategy);
		successHandler.setRequestCache(requestCache);
		successHandler.setTargetUrlParameter(authcProperties.getTargetUrlParameter());
		successHandler.setUseReferer(authcProperties.isUseReferer());
		return successHandler;
	}

	@Bean
	public LdapAuthenticationFailureHandler ldapAuthenticationFailureHandler(
			SecurityLdapProperties ldapProperties,
			SecurityLdapAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties,
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Qualifier("upcRedirectStrategy") RedirectStrategy redirectStrategy) {
		LdapAuthenticationFailureHandler failureHandler = new LdapAuthenticationFailureHandler();
		failureHandler.setAllowSessionCreation(sessionMgtProperties.isAllowSessionCreation());
		failureHandler.setRedirectStrategy(redirectStrategy);
		failureHandler.setUseForward(authcProperties.isUseForward());
		return failureHandler;
	}
	
}
