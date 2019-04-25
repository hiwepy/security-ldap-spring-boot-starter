package org.springframework.security.boot;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.boot.ldap.authentication.AuthoritiesMapperPolicy;
import org.springframework.security.boot.ldap.authentication.DirContextPolicy;
import org.springframework.security.boot.ldap.authentication.LdapUsernamePasswordAuthenticationToken;
import org.springframework.security.boot.ldap.property.SecurityActiveDirectoryLdapProperties;
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

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityLdapProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityLdapProperties.class, SecurityBizProperties.class })
public class SecurityLdapAutoConfiguration {

	@Autowired
	private SecurityLdapProperties ldapProperties;

	public LdapContextSource ldapContextSource() {
		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
				ldapProperties.getAuthc().getProviderUrl());
		contextSource.assembleProviderUrlString(ldapProperties.getAuthc().getLdapUrls());
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
	public DirContextAuthenticationStrategy authenticationStrategy() {
		if (DirContextPolicy.DEFAULT_TLS.equals(ldapProperties.getAuthc().getDirContextPolicy())) {
			return new DefaultTlsDirContextAuthenticationStrategy();
		} else if (DirContextPolicy.EXTERNAL_TLS.equals(ldapProperties.getAuthc().getDirContextPolicy())) {
			return new ExternalTlsDirContextAuthenticationStrategy();
		} else if (DirContextPolicy.DIGEST_MD5.equals(ldapProperties.getAuthc().getDirContextPolicy())) {
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
	public BaseLdapPathContextSource contextSource(DirContextAuthenticationStrategy authenticationStrategy,
			AuthenticationSource authenticationSource) {

		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
				ldapProperties.getAuthc().getProviderUrl());

		contextSource.assembleProviderUrlString(ldapProperties.getAuthc().getLdapUrls());
		contextSource.setAnonymousReadOnly(ldapProperties.getAuthc().isAnonymousReadOnly());
		contextSource.setAuthenticationSource(authenticationSource);
		contextSource.setAuthenticationStrategy(authenticationStrategy);
		contextSource.setBase(ldapProperties.getAuthc().getBase());
		contextSource.setBaseEnvironmentProperties(ldapProperties.getAuthc().getBaseEnvironmentProperties());
		contextSource.setCacheEnvironmentProperties(ldapProperties.getAuthc().isCacheEnvironmentProperties());
		contextSource.setPassword(ldapProperties.getAuthc().getPassword());
		contextSource.setPooled(ldapProperties.getAuthc().isPooled());
		contextSource.setReferral(ldapProperties.getAuthc().getReferral());
		contextSource.setUrls(ldapProperties.getAuthc().getUrls());
		contextSource.setUserDn(ldapProperties.getAuthc().getUserDn());

		return contextSource;
	}

	@Bean
	@ConditionalOnMissingBean
	public LdapUserSearch userSearch(BaseLdapPathContextSource contextSource) {

		FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(ldapProperties.getAuthc().getSearchBase(),
				ldapProperties.getAuthc().getSearchFilter(), contextSource);

		userSearch.setDerefLinkFlag(ldapProperties.getAuthc().isDerefLinkFlag());
		userSearch.setReturningAttributes(ldapProperties.getAuthc().getReturningAttrs());
		userSearch.setSearchSubtree(ldapProperties.getAuthc().isSearchSubtree());
		userSearch.setSearchTimeLimit(ldapProperties.getAuthc().getSearchTimeLimit());

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
	public GrantedAuthoritiesMapper authoritiesMapper(RoleHierarchy roleHierarchy) {
		if (AuthoritiesMapperPolicy.ROLE_HIERARCHY.equals(ldapProperties.getAuthc().getAuthoritiesMapperPolicy())) {
			return new RoleHierarchyAuthoritiesMapper(roleHierarchy);
		} else if (AuthoritiesMapperPolicy.SIMPLE.equals(ldapProperties.getAuthc().getAuthoritiesMapperPolicy())) {
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
	public LdapAuthoritiesPopulator ldapAuthoritiesPopulator(BaseLdapPathContextSource contextSource) {

		SecurityLdapPopulatorProperties populatorProperties = ldapProperties.getPopulator();
		
		DefaultLdapAuthoritiesPopulator authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(contextSource,
				ldapProperties.getAuthc().getGroupSearchBase());
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
			authenticationProvider.setSearchFilter(ldapProperties.getAuthc().getSearchFilter());
			authenticationProvider.setUseAuthenticationRequestCredentials(ldapProperties.getAuthc().isUseAuthenticationRequestCredentials());
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
		authenticationProvider.setHideUserNotFoundExceptions(ldapProperties.getAuthc().isHideUserNotFoundExceptions());
		authenticationProvider.setMessageSource(messageSource);
		authenticationProvider.setUseAuthenticationRequestCredentials(ldapProperties.getAuthc().isUseAuthenticationRequestCredentials());
		authenticationProvider.setUserDetailsContextMapper(userDetailsContextMapper);

		return authenticationProvider;
	}

}
