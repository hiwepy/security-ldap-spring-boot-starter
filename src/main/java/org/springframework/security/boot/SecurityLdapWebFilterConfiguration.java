package org.springframework.security.boot;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.AuthenticationSource;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.ajax.AjaxAwareAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.ajax.AjaxAwareAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.ajax.AjaxAwareLoginProcessingFilter;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.authentication.NullLdapAuthoritiesPopulator;
import org.springframework.security.ldap.authentication.SpringSecurityAuthenticationSource;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore(name = { 
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration",
	"org.springframework.security.boot.SecurityBizWebFilterConfiguration"   // spring-boot-starter-security-biz
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityLdapProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityLdapProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityLdapWebFilterConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private SecurityLdapProperties ldapProperties;
	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;


	@Bean
	protected BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
		return new WebAuthenticationDetailsSource();
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationSuccessHandler successHandler(ObjectMapper mapper) {
		
		// Ajax Login
		if(bizProperties.isLoginAjax()) {
			AjaxAwareAuthenticationSuccessHandler successHandler = new AjaxAwareAuthenticationSuccessHandler(mapper, jwtProperties);
			return successHandler;
		}
		// Form Login
		else {
			SimpleUrlAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
			successHandler.setDefaultTargetUrl(bizProperties.getSuccessUrl());
			return successHandler;
		}
		
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationFailureHandler failureHandler() {
		// Ajax Login
		if(bizProperties.isLoginAjax()) {
			return new AjaxAwareAuthenticationFailureHandler(bizProperties.getFailureUrl());
		}
		// Form Login
		else {
			return new SimpleUrlAuthenticationFailureHandler(bizProperties.getFailureUrl());
		}
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionAuthenticationStrategy sessionStrategy() {
		return new NullAuthenticatedSessionStrategy();
	}

	@Bean
	@ConditionalOnMissingBean
	public RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
	}

	public static final String JWT_TOKEN_HEADER_PARAM = "X-Authorization";
    public static final String FORM_BASED_LOGIN_ENTRY_POINT = "/api/auth/login";
    public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";
    public static final String TOKEN_REFRESH_ENTRY_POINT = "/api/auth/token";
    
    @Bean
	@ConditionalOnMissingBean
	public ObjectMapper objectMapper() {
		return new ObjectMapper();
	}
    
    @Bean
	@ConditionalOnMissingBean
	public AjaxAwareLoginProcessingFilter jwtAjaxLoginProcessingFilter(AuthenticationFailureHandler failureHandler,
			AuthenticationManager authenticationManager, ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy, ObjectMapper objectMapper) throws Exception {
        //AjaxUsernamePasswordAuthenticationFilter filter = new AjaxUsernamePasswordAuthenticationFilter(FORM_BASED_LOGIN_ENTRY_POINT, successHandler, failureHandler, objectMapper);
        //filter.setAuthenticationManager(authenticationManager);
        return null;
    }
    
    
   
    @Bean
	@ConditionalOnMissingBean
	public ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider(
    		AuthenticationFailureHandler failureHandler,
    		GrantedAuthoritiesMapper authoritiesMapper, ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy) throws Exception {
        
        ActiveDirectoryLdapAuthenticationProvider authenticationProvider  = new ActiveDirectoryLdapAuthenticationProvider(failureHandler, tokenExtractor, matcher);
        
        authenticationProvider.setAuthoritiesMapper(authoritiesMapper);
        authenticationProvider.setConvertSubErrorCodesToExceptions(true);
        //authenticationProvider.setMessageSource(messageSource);
        authenticationProvider.setSearchFilter(searchFilter);
        authenticationProvider.setUseAuthenticationRequestCredentials(ldapProperties.isUseAuthenticationRequestCredentials());
        authenticationProvider.setUserDetailsContextMapper(userDetailsContextMapper);
        
        return authenticationProvider;
    }
    
    
    @Bean
   	@ConditionalOnMissingBean
   	public DirContextAuthenticationStrategy authenticationStrategy() {
    	return new SimpleDirContextAuthenticationStrategy();
    }
    
    @Bean
   	@ConditionalOnMissingBean
   	public AuthenticationSource authenticationSource() {
    	return new SpringSecurityAuthenticationSource();
    }

	@Bean
	@ConditionalOnMissingBean
	public BaseLdapPathContextSource contextSource(DirContextAuthenticationStrategy authenticationStrategy,
			AuthenticationSource authenticationSource) {

		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
				ldapProperties.getProviderUrl());

		contextSource.assembleProviderUrlString(ldapProperties.getLdapUrls());
		contextSource.setAnonymousReadOnly(ldapProperties.isAnonymousReadOnly());
		contextSource.setAuthenticationSource(authenticationSource);
		contextSource.setAuthenticationStrategy(authenticationStrategy);
		contextSource.setBase(ldapProperties.getBase());
		contextSource.setBaseEnvironmentProperties(ldapProperties.getBaseEnvironmentProperties());
		contextSource.setCacheEnvironmentProperties(ldapProperties.isCacheEnvironmentProperties());
		contextSource.setPassword(ldapProperties.getPassword());
		contextSource.setPooled(ldapProperties.isPooled());
		contextSource.setReferral(ldapProperties.getReferral());
		contextSource.setUrls(ldapProperties.getUrls());
		contextSource.setUserDn(ldapProperties.getUserDn());

		return contextSource;
	}
    
	
	@Bean
   	@ConditionalOnMissingBean
   	public LdapUserSearch userSearch(BaseLdapPathContextSource contextSource) {
    	
		FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(
				ldapProperties.getSearchBase(), ldapProperties.getSearchFilter(),
				contextSource);
    	
		userSearch.setDerefLinkFlag(ldapProperties.isDerefLinkFlag());
		userSearch.setReturningAttributes(ldapProperties.getReturningAttrs());
		userSearch.setSearchSubtree(ldapProperties.isSearchSubtree());
		userSearch.setSearchTimeLimit(ldapProperties.getSearchTimeLimit());
    	
   		return userSearch;
   	}

    @Bean
   	@ConditionalOnMissingBean
   	public LdapAuthenticator authenticator(BaseLdapPathContextSource contextSource,
   			LdapUserSearch userSearch) {
    	
    	BindAuthenticator authenticator = new BindAuthenticator(contextSource);
    	
    	//authenticator.setMessageSource(messageSource);
    	//authenticator.setUserDnPatterns(dnPattern);
    	authenticator.setUserSearch(userSearch);
    	
   		return authenticator;
   	}
    
    @Bean
   	@ConditionalOnMissingBean
   	public LdapAuthoritiesPopulator authoritiesPopulator(BaseLdapPathContextSource contextSource) {
    	
    	DefaultLdapAuthoritiesPopulator authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(contextSource, ldapProperties.getGroupSearchBase());
    	/*authoritiesPopulator.setConvertToUpperCase(convertToUpperCase);
    	authoritiesPopulator.setDefaultRole(defaultRole);
    	authoritiesPopulator.setGroupRoleAttribute(groupRoleAttribute);
    	authoritiesPopulator.setGroupSearchFilter(groupSearchFilter);
    	authoritiesPopulator.setIgnorePartialResultException(ignore);
    	authoritiesPopulator.setRolePrefix(rolePrefix);
    	authoritiesPopulator.setSearchSubtree(searchSubtree);*/
   		
   		return authoritiesPopulator;
   	}
    
    @Bean
   	@ConditionalOnMissingBean
   	public GrantedAuthoritiesMapper authoritiesMapper() {
   		return new NullAuthoritiesMapper();
   	}
    
    @Bean
   	@ConditionalOnMissingBean
   	public UserDetailsContextMapper userDetailsContextMapper() {
   		return new LdapUserDetailsMapper();
   	}
	
    @Bean
   	@ConditionalOnMissingBean
   	public LdapAuthenticationProvider ldapAuthenticationProvider(
		LdapAuthenticator authenticator,
		LdapAuthoritiesPopulator authoritiesPopulator,
		GrantedAuthoritiesMapper authoritiesMapper,
		UserDetailsContextMapper userDetailsContextMapper) throws Exception {
       
       LdapAuthenticationProvider authenticationProvider = new LdapAuthenticationProvider(authenticator, authoritiesPopulator);
       
       authenticationProvider.setAuthoritiesMapper(authoritiesMapper);
       authenticationProvider.setHideUserNotFoundExceptions(false);
       //authenticationProvider2.setMessageSource(messageSource);
       authenticationProvider.setUseAuthenticationRequestCredentials(ldapProperties.isUseAuthenticationRequestCredentials());
       authenticationProvider.setUserDetailsContextMapper(userDetailsContextMapper);
       
       return authenticationProvider;
   }
     
	
	@Bean
	@ConditionalOnMissingBean
	public AbstractAuthenticationProcessingFilter authenticationFilter(AuthenticationFailureHandler failureHandler,
			AuthenticationManager authenticationManager, ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy) {

		UsernamePasswordAuthenticationFilter authenticationFilter = new UsernamePasswordAuthenticationFilter();

		authenticationFilter.setAllowSessionCreation(bizProperties.isAllowSessionCreation());
		authenticationFilter.setApplicationEventPublisher(publisher);
		authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
		authenticationFilter.setAuthenticationFailureHandler(failureHandler);
		authenticationFilter.setAuthenticationManager(authenticationManager);
		authenticationFilter.setAuthenticationSuccessHandler(successHandler);
		authenticationFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getLoginUrlPatterns())) {
			authenticationFilter.setFilterProcessesUrl(bizProperties.getLoginUrlPatterns());
		}
		// authenticationFilter.setMessageSource(messageSource);
		authenticationFilter.setPasswordParameter(bizProperties.getPasswordParameter());
		authenticationFilter.setPostOnly(bizProperties.isPostOnly());
		authenticationFilter.setRememberMeServices(rememberMeServices);
		authenticationFilter.setSessionAuthenticationStrategy(sessionStrategy);
		authenticationFilter.setUsernameParameter(bizProperties.getUsernameParameter());

		return authenticationFilter;
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationEntryPoint authenticationEntryPoint() {
		
		LoginUrlAuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint(bizProperties.getLoginUrl());
		entryPoint.setForceHttps(bizProperties.isForceHttps());
		entryPoint.setUseForward(bizProperties.isUseForward());
		
		return entryPoint;
	}
	
	/**
	 * 系统登录注销过滤器；默认：org.springframework.security.web.authentication.logout.LogoutFilter
	 */
	@Bean
	@ConditionalOnMissingBean
	public LogoutFilter logoutFilter() {
		// 登录注销后的重定向地址：直接进入登录页面
		LogoutFilter logoutFilter = new LogoutFilter(bizProperties.getLoginUrl(), new SecurityContextLogoutHandler());
		logoutFilter.setFilterProcessesUrl(bizProperties.getLogoutUrlPatterns());
		return logoutFilter;
	}

	/*@Bean
	public FilterRegistrationBean<HttpParamsFilter> httpParamsFilter() {
		FilterRegistrationBean<HttpParamsFilter> filterRegistrationBean = new FilterRegistrationBean<HttpParamsFilter>();
		filterRegistrationBean.setFilter(new HttpParamsFilter());
		filterRegistrationBean.setOrder(-999);
		filterRegistrationBean.addUrlPatterns("/");
		return filterRegistrationBean;
	}*/

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
