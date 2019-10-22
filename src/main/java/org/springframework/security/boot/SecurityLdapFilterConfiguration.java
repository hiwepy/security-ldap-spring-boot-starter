package org.springframework.security.boot;

import java.util.Arrays;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.ldap.authentication.LadpAuthenticationProcessingFilter;
import org.springframework.security.boot.ldap.authentication.LdapAuthenticationFailureHandler;
import org.springframework.security.boot.ldap.authentication.LdapAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticationProvider;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.cors.CorsConfigurationSource;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnClass({ AbstractSecurityWebApplicationInitializer.class, SessionCreationPolicy.class })
@ConditionalOnProperty(prefix = SecurityLdapProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityLdapProperties.class, SecurityBizProperties.class })
public class SecurityLdapFilterConfiguration {

	@Configuration
	@ConditionalOnProperty(prefix = SecurityLdapProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityLdapProperties.class, SecurityBizProperties.class })
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 5)
	static class LdapWebSecurityConfigurerAdapter extends SecurityBizConfigurerAdapter {
    	
    	private final AuthenticationManager authenticationManager;
	    private final ObjectMapper objectMapper;
	    private final RememberMeServices rememberMeServices;

	    private final SecurityBizProperties bizProperties;
		private final SecurityLdapProperties ldapProperties;
 	    private final AbstractLdapAuthenticationProvider authenticationProvider;
 	    private final LdapAuthenticationSuccessHandler authenticationSuccessHandler;
 	    private final LdapAuthenticationFailureHandler authenticationFailureHandler;

		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		
		public LdapWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
				SecurityLdapProperties ldapProperties,
				
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<SessionRegistry> sessionRegistryProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				
   				ObjectProvider<AbstractLdapAuthenticationProvider> authenticationProvider,
   				ObjectProvider<LdapAuthenticationSuccessHandler> authenticationSuccessHandler,
   				ObjectProvider<LdapAuthenticationFailureHandler> authenticationFailureHandler,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				ObjectProvider<CorsConfigurationSource> configurationSourceProvider,
   				
   				@Qualifier("jwtAuthenticatingFailureCounter") ObjectProvider<AuthenticatingFailureCounter> authenticatingFailureCounter,
				@Qualifier("jwtSessionAuthenticationStrategy") ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider) {
		    
			super(bizProperties, csrfTokenRepositoryProvider.getIfAvailable(), configurationSourceProvider.getIfAvailable());
			
			this.bizProperties = bizProperties;
			this.ldapProperties = ldapProperties;
			
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
		}

		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
   			AuthenticationManager parentManager = authenticationManager == null ? super.authenticationManagerBean() : authenticationManager;
			ProviderManager authenticationManager = new ProviderManager( Arrays.asList(authenticationProvider), parentManager);
			// 不擦除认证密码，擦除会导致TokenBasedRememberMeServices因为找不到Credentials再调用UserDetailsService而抛出UsernameNotFoundException
			authenticationManager.setEraseCredentialsAfterAuthentication(false);
			return authenticationManager;
		}
		
		public LadpAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
			
			// Form Login With LDAP 
			LadpAuthenticationProcessingFilter authenticationFilter = new LadpAuthenticationProcessingFilter(objectMapper, ldapProperties);
			
			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(bizProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(ldapProperties.getAuthc().isPostOnly()).to(authenticationFilter::setPostOnly);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			 
			return authenticationFilter;
		}
		
		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			// 配置LDAP的验证方式
			auth.authenticationProvider(authenticationProvider);
			super.configure(auth);
		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.antMatcher(ldapProperties.getAuthc().getLoginUrlPatterns())
				.addFilterBefore(authenticationProcessingFilter(), PostRequestAuthenticationProcessingFilter.class);
			super.configure(http);
		}
		
		@Override
	    public void configure(WebSecurity web) throws Exception {
	    }
		
	}

	 

}
