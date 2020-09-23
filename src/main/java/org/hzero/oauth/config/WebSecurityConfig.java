package org.hzero.oauth.config;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import org.hzero.oauth.domain.service.ClearResourceFilter;
import org.hzero.oauth.domain.service.ClearResourceService;
import org.hzero.oauth.security.config.SecurityProperties;
import org.hzero.oauth.security.custom.CustomAuthenticationDetailsSource;
import org.hzero.oauth.security.custom.CustomAuthenticationFailureHandler;
import org.hzero.oauth.security.custom.CustomAuthenticationSuccessHandler;
import org.hzero.oauth.security.custom.CustomLogoutSuccessHandler;
import org.hzero.oauth.security.sms.SmsAuthenticationDetailsSource;
import org.hzero.oauth.security.sms.SmsAuthenticationFailureHandler;
import org.hzero.oauth.security.sms.SmsAuthenticationProvider;
import org.hzero.oauth.security.sms.config.EnableSmsLogin;
import org.hzero.oauth.security.sms.config.SmsLoginConfigurer;
import org.hzero.sso.core.config.EnableSsoLogin;
import org.hzero.sso.core.config.SsoAuthenticationEntryPoint;
import org.hzero.sso.core.config.SsoProperties;
import org.hzero.starter.social.core.configuration.EnableSocialLogin;

/**
 * @author bojiangzhou
 */
@EnableSocialLogin
@EnableSmsLogin
@EnableSsoLogin
@Configuration
@Order(org.springframework.boot.autoconfigure.security.SecurityProperties.BASIC_AUTH_ORDER)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SecurityProperties securityProperties;
    @Autowired
    private SsoProperties ssoProperties;
    @Autowired
    private CustomAuthenticationDetailsSource detailsSource;
    @Autowired
    private CustomAuthenticationFailureHandler authenticationFailureHandler;
    @Autowired
    private CustomAuthenticationSuccessHandler authenticationSuccessHandler;
    @Autowired
    private CustomLogoutSuccessHandler customLogoutSuccessHandler;
    @Autowired
    private ClearResourceService clearResourceService;

    @Autowired(required = false)
    private SmsAuthenticationDetailsSource smsAuthenticationDetailsSource;
    @Autowired(required = false)
    private SmsAuthenticationFailureHandler smsAuthenticationFailureHandler;
    @Autowired(required = false)
    private SmsAuthenticationProvider smsAuthenticationProvider;

    @Autowired(required = false)
    private SsoAuthenticationEntryPoint ssoAuthenticationEntryPoint;

    private static final String[] PERMIT_PATHS = new String[] {
                "/login", "/login/**", "/open-bind", "/token/**", "/pass-page/**", "/admin/**",
                "/v2/choerodon/**", "/choerodon/**", "/public/**", "/password/**",
                "/admin/**","/static/**", "/saml/metadata", "/actuator/**"
    };

    @Override
    public void configure(HttpSecurity http) throws Exception {
        String[] permitPaths = ArrayUtils.addAll(PERMIT_PATHS, securityProperties.getPermitPaths());

        http
                .authorizeRequests()
                .antMatchers (permitPaths)
                .permitAll()
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage(securityProperties.getLogin().getRelativePage())
                .authenticationDetailsSource(detailsSource)
                .failureHandler(authenticationFailureHandler)
                .successHandler(authenticationSuccessHandler)
                .and()
                .logout().deleteCookies("access_token").invalidateHttpSession(true)
                .logoutSuccessHandler(customLogoutSuccessHandler)
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .and()
                .csrf()
                .disable()
        ;

        // 配置短信登录方式
        SmsLoginConfigurer smsLoginConfigurer = new SmsLoginConfigurer();
        smsLoginConfigurer
            .authenticationDetailsSource(smsAuthenticationDetailsSource)
            .successHandler(authenticationSuccessHandler)
            .failureHandler(smsAuthenticationFailureHandler)
            .mobileParameter(securityProperties.getLogin().getMobileParameter())
            .loginProcessingUrl(securityProperties.getLogin().getMobileLoginProcessUrl())
        ;
        http.apply(smsLoginConfigurer);
        http.authenticationProvider(smsAuthenticationProvider);

        // SSO 认证
        if (ssoProperties.getSso().isEnabled()) {
            http
                .exceptionHandling()
                .authenticationEntryPoint(ssoAuthenticationEntryPoint)
                ;
        }
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public FilterRegistrationBean<ClearResourceFilter> registerClearResourceFilter() {
        FilterRegistrationBean<ClearResourceFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new ClearResourceFilter(clearResourceService));
        registration.addUrlPatterns("/*");
        registration.setName("clearResourceFilter");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }


}
