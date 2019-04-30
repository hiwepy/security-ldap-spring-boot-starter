package org.springframework.security.boot;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.ldap.authentication.LadpAuthenticationProcessingFilter;
import org.springframework.security.boot.ldap.authentication.LdapAuthenticationFailureHandler;
import org.springframework.security.boot.ldap.authentication.LdapAuthenticationSuccessHandler;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticationProvider;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

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
    @Order(107)
	static class JwtAuthcWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {

    	private ApplicationEventPublisher eventPublisher;
    	
    	private final AuthenticationManager authenticationManager;
	    private final ObjectMapper objectMapper;
	    private final RememberMeServices rememberMeServices;
	    
		private final SecurityLdapProperties ldapProperties;
 	    private final AbstractLdapAuthenticationProvider authenticationProvider;
 	    private final LdapAuthenticationSuccessHandler authenticationSuccessHandler;
 	    private final LdapAuthenticationFailureHandler authenticationFailureHandler;
 	    private final CaptchaResolver captchaResolver;

		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		
		public JwtAuthcWebSecurityConfigurerAdapter(
				
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<SessionRegistry> sessionRegistryProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				
   				SecurityLdapProperties ldapProperties,
   				ObjectProvider<AbstractLdapAuthenticationProvider> authenticationProvider,
   				ObjectProvider<LdapAuthenticationSuccessHandler> authenticationSuccessHandler,
   				ObjectProvider<LdapAuthenticationFailureHandler> authenticationFailureHandler,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				
   				@Qualifier("jwtAuthenticatingFailureCounter") ObjectProvider<AuthenticatingFailureCounter> authenticatingFailureCounter,
				@Qualifier("jwtSessionAuthenticationStrategy") ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider) {
		    
			
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			
   			this.ldapProperties = ldapProperties;
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			this.captchaResolver = captchaResolverProvider.getIfAvailable();
   			
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
		}

		@Bean
		public LadpAuthenticationProcessingFilter ladpAuthenticationProcessingFilter() {
			
			// Form Login With LDAP 
			LadpAuthenticationProcessingFilter authcFilter = new LadpAuthenticationProcessingFilter(objectMapper, ldapProperties);
			
			authcFilter.setCaptchaParameter(ldapProperties.getCaptcha().getParamName());
			// 是否验证码必填
			authcFilter.setCaptchaRequired(ldapProperties.getCaptcha().isRequired());
			// 登陆失败重试次数，超出限制需要输入验证码
			authcFilter.setRetryTimesWhenAccessDenied(ldapProperties.getCaptcha().getRetryTimesWhenAccessDenied());
			// 验证码解析器
			authcFilter.setCaptchaResolver(captchaResolver);
			
			authcFilter.setAllowSessionCreation(ldapProperties.getSessionMgt().isAllowSessionCreation());
			authcFilter.setApplicationEventPublisher(eventPublisher);
			authcFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
			authcFilter.setAuthenticationManager(authenticationManager);
			authcFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
			authcFilter.setContinueChainBeforeSuccessfulAuthentication(false);
			if (StringUtils.hasText(ldapProperties.getAuthc().getLoginUrlPatterns())) {
				authcFilter.setFilterProcessesUrl(ldapProperties.getAuthc().getLoginUrlPatterns());
			}
			//authcFilter.setMessageSource(messageSource);
			authcFilter.setPasswordParameter(ldapProperties.getAuthc().getPasswordParameter());
			authcFilter.setPostOnly(ldapProperties.getAuthc().isPostOnly());
			authcFilter.setRememberMeServices(rememberMeServices);
			authcFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
			authcFilter.setUsernameParameter(ldapProperties.getAuthc().getUsernameParameter());

			return authcFilter;
		}
		
		@Override
		protected void configure(AuthenticationManagerBuilder auth) {
			// 配置LDAP的验证方式
			auth.authenticationProvider(authenticationProvider);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.addFilterBefore(ladpAuthenticationProcessingFilter(), PostRequestAuthenticationProcessingFilter.class);
		}
		
		@Override
	    public void configure(WebSecurity web) throws Exception {
	    	web.ignoring().antMatchers(ldapProperties.getAuthc().getLoginUrlPatterns());
	    }

		@Override
		public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
			this.eventPublisher = applicationEventPublisher;
		}
		
	}

	 

}
