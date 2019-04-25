package org.springframework.security.boot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.ldap.authentication.LadpAuthenticationProcessingFilter;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticationProvider;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureAfter(SecurityBizFilterAutoConfiguration.class)
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityLdapProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityLdapProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityLdapFilterConfiguration extends WebSecurityConfigurerAdapter
		implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;
	@Autowired
	private SecurityLdapProperties ldapProperties;
	
	@Bean
	public LadpAuthenticationProcessingFilter ladpAuthenticationProcessingFilter(
			AuthenticationManager authenticationManager, 
			AuthenticationSuccessHandler successHandler, 
    		AuthenticationFailureHandler failureHandler,
			RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy,
			@Autowired(required = false) CaptchaResolver captchaResolver,
			MessageSource messageSource,
			ObjectMapper objectMapper) {
		
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
		authcFilter.setAuthenticationFailureHandler(failureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(successHandler);
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(ldapProperties.getAuthc().getLoginUrlPatterns())) {
			authcFilter.setFilterProcessesUrl(ldapProperties.getAuthc().getLoginUrlPatterns());
		}
		authcFilter.setMessageSource(messageSource);
		authcFilter.setPasswordParameter(ldapProperties.getAuthc().getPasswordParameter());
		authcFilter.setPostOnly(ldapProperties.getAuthc().isPostOnly());
		authcFilter.setRememberMeServices(rememberMeServices);
		
		authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
		
		authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
		authcFilter.setUsernameParameter(ldapProperties.getAuthc().getUsernameParameter());

		return authcFilter;
	}
	
	@Autowired
	private LadpAuthenticationProcessingFilter ladpAuthenticationProcessingFilter;
	@Autowired
	private AbstractLdapAuthenticationProvider ldapAuthenticationProvider;
	 
	@Override
	protected void configure(AuthenticationManagerBuilder auth) {
		// 配置LDAP的验证方式
		auth.authenticationProvider(ldapAuthenticationProvider);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(ladpAuthenticationProcessingFilter, PostRequestAuthenticationProcessingFilter.class);
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

}