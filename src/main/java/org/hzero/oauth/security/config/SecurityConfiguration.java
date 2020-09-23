package org.hzero.oauth.security.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.session.SessionRepository;

import org.hzero.boot.oauth.domain.repository.BaseClientRepository;
import org.hzero.boot.oauth.domain.repository.BaseLdapRepository;
import org.hzero.boot.oauth.domain.repository.BasePasswordPolicyRepository;
import org.hzero.boot.oauth.domain.service.BaseUserService;
import org.hzero.boot.oauth.domain.service.PasswordErrorTimesService;
import org.hzero.boot.oauth.policy.PasswordPolicyManager;
import org.hzero.core.captcha.CaptchaImageHelper;
import org.hzero.core.redis.RedisHelper;
import org.hzero.oauth.domain.repository.AuditLoginRepository;
import org.hzero.oauth.domain.repository.ClientRepository;
import org.hzero.oauth.domain.repository.UserRepository;
import org.hzero.oauth.domain.service.AuditLoginService;
import org.hzero.oauth.domain.service.impl.AuditLoginServiceImpl;
import org.hzero.oauth.infra.constant.Constants;
import org.hzero.oauth.infra.encrypt.EncryptClient;
import org.hzero.oauth.security.custom.*;
import org.hzero.oauth.security.custom.processor.login.LoginSuccessProcessor;
import org.hzero.oauth.security.custom.processor.logout.LogoutSuccessProcessor;
import org.hzero.oauth.security.resource.ResourceMatcher;
import org.hzero.oauth.security.resource.impl.MobileResourceMatcher;
import org.hzero.oauth.security.service.*;
import org.hzero.oauth.security.service.impl.*;
import org.hzero.oauth.security.social.*;
import org.hzero.oauth.security.sso.DefaultSsoUserAccountService;
import org.hzero.oauth.security.sso.DefaultSsoUserDetailsBuilder;
import org.hzero.oauth.security.util.LoginUtil;
import org.hzero.sso.core.config.SsoProperties;
import org.hzero.sso.core.domain.repository.DomainRepository;
import org.hzero.sso.core.security.service.SsoUserAccountService;
import org.hzero.sso.core.security.service.SsoUserDetailsBuilder;
import org.hzero.starter.social.core.provider.SocialProviderRepository;
import org.hzero.starter.social.core.provider.SocialUserProviderRepository;
import org.hzero.starter.social.core.security.SocialAuthenticationProvider;
import org.hzero.starter.social.core.security.SocialSuccessHandler;
import org.hzero.starter.social.core.security.SocialUserDetailsService;

/**
 * Oauth 服务配置
 *
 * @author bojiangzhou 2018/08/02
 */
@Configuration
@EnableConfigurationProperties({SecurityProperties.class})
public class SecurityConfiguration {

    @Autowired
    private CaptchaImageHelper captchaImageHelper;
    @Autowired
    private RedisHelper redisHelper;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private SecurityProperties securityProperties;
    @Autowired
    private RedisConnectionFactory redisConnectionFactory;
    @Autowired
    private LoginUtil loginUtil;

    @Autowired(required = false)
    private DomainRepository domainRepository;
    @Autowired
    private SsoProperties ssoProperties;
    @Autowired
    private BaseUserService baseUserService;
    @Autowired
    private BaseLdapRepository baseLdapRepository;
    @Autowired
    private BasePasswordPolicyRepository basePasswordPolicyRepository;
    @Autowired
    private BaseClientRepository baseClientRepository;
    @Autowired
    private PasswordErrorTimesService passwordErrorTimesService;
    @Autowired
    private PasswordPolicyManager passwordPolicyManager;

    @Autowired
    private SessionRepository<?> sessionRepository;
    @Autowired
    private AuditLoginRepository auditLoginRepository;

    @Bean
    @ConditionalOnMissingBean(ResourceMatcher.class)
    @ConditionalOnProperty(prefix = SecurityProperties.PREFIX, name = "custom-resource-matcher", havingValue = "true")
    public ResourceMatcher resourceMatcher () {
        return new MobileResourceMatcher();
    }

    /**
     * 用户账户业务服务
     */
    @Bean
    @ConditionalOnMissingBean(UserAccountService.class)
    public UserAccountService userAccountService() {
        return new DefaultUserAccountService(this.userRepository, this.baseUserService, this.passwordPolicyManager,
                this.basePasswordPolicyRepository, this.baseClientRepository, this.securityProperties);
    }

    /**
     * 登录记录业务服务
     */
    @Bean
    @ConditionalOnMissingBean(LoginRecordService.class)
    public LoginRecordService loginRecordService() {
        return new DefaultLoginRecordService(baseUserService, passwordErrorTimesService, basePasswordPolicyRepository, redisHelper);
    }

    @Bean
    @ConditionalOnMissingBean(UserDetailsWrapper.class)
    public UserDetailsWrapper userDetailsWrapper(RedisHelper redisHelper) {
        return new DefaultUserDetailsWrapper(userRepository, redisHelper);
    }

    @Bean
    @ConditionalOnMissingBean(ClientDetailsWrapper.class)
    public ClientDetailsWrapper clientDetailsWrapper(ClientRepository clientRepository) {
        return new DefaultClientDetailsWrapper(clientRepository);
    }

    @Bean
    @ConditionalOnMissingBean(UserDetailsBuilder.class)
    public UserDetailsBuilder userDetailsBuilder(UserDetailsWrapper userDetailsWrapper) {
        return new DefaultUserDetailsBuilder(userDetailsWrapper, domainRepository, ssoProperties, userAccountService());
    }
    
    /**
     * Sso用户账户业务服务
     */
    @Bean
    @ConditionalOnMissingBean(SsoUserAccountService.class)
    public SsoUserAccountService ssoUserAccountService() {
        return new DefaultSsoUserAccountService(userRepository, securityProperties);
    }
    
    @Bean
    @ConditionalOnMissingBean(SsoUserDetailsBuilder.class)
    public SsoUserDetailsBuilder ssoUserDetailsBuilder(UserDetailsWrapper userDetailsWrapper) {
        return new DefaultSsoUserDetailsBuilder(userDetailsWrapper, domainRepository, ssoProperties, userAccountService());
    }

    @Bean
    @ConditionalOnMissingBean(CustomAuthenticationDetailsSource.class)
    public CustomAuthenticationDetailsSource authenticationDetailsSource () {
        return new CustomAuthenticationDetailsSource(captchaImageHelper);
    }

    @Bean
    @ConditionalOnMissingBean(CustomAuthenticationSuccessHandler.class)
    public CustomAuthenticationSuccessHandler authenticationSuccessHandler (List<LoginSuccessProcessor> successProcessors) {
        return new CustomAuthenticationSuccessHandler(securityProperties, successProcessors);
    }

    @Bean
    @ConditionalOnMissingBean(AuditLoginService.class)
    public AuditLoginService auditLoginService () {
        return new AuditLoginServiceImpl(auditLoginRepository, userRepository, tokenStore());
    }

    @Bean
    @ConditionalOnMissingBean(CustomAuthenticationFailureHandler.class)
    public CustomAuthenticationFailureHandler authenticationFailureHandler () {
        return new CustomAuthenticationFailureHandler(loginRecordService(), securityProperties, auditLoginService());
    }

    @Bean
    @ConditionalOnMissingBean(CustomLogoutSuccessHandler.class)
    public CustomLogoutSuccessHandler logoutSuccessHandler (List<LogoutSuccessProcessor> postProcessors) {
        return new CustomLogoutSuccessHandler(tokenStore(), loginRecordService(), securityProperties, ssoProperties,domainRepository,
                userAccountService() , postProcessors);
    }

    @Bean
    @ConditionalOnMissingBean(CustomUserDetailsService.class)
    public CustomUserDetailsService userDetailsService (UserAccountService userAccountService,
                                                        UserDetailsBuilder userDetailsBuilder,
                                                        LoginRecordService loginRecordService) {
        return new CustomUserDetailsService(userAccountService, userDetailsBuilder, loginRecordService);
    }

    //@Bean
    //@ConditionalOnMissingBean(CustomClientDetailsService.class)
    //public CustomClientDetailsService clientDetailsService (BaseClientRepository baseClientRepository, ClientDetailsWrapper clientDetailsWrapper) {
    //    return new CustomClientDetailsService(baseClientRepository, clientDetailsWrapper);
    //}
    
    @Bean
    @ConditionalOnMissingBean(CustomAuthenticationProvider.class)
    public CustomAuthenticationProvider authenticationProvider (CustomUserDetailsService userDetailsService,
                                                                EncryptClient encryptClient,
                                                                PasswordEncoder passwordEncoder) {
        CustomAuthenticationProvider provider = new CustomAuthenticationProvider(
                userDetailsService, baseLdapRepository,
                userAccountService(), loginRecordService(),
                captchaImageHelper, securityProperties,
                encryptClient, userRepository);

        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    @ConditionalOnMissingBean(CustomAuthenticationKeyGenerator.class)
    public CustomAuthenticationKeyGenerator authenticationKeyGenerator () {
        return new CustomAuthenticationKeyGenerator(loginUtil);
    }

    @Bean
    @ConditionalOnMissingBean(CustomRedisTokenStore.class)
    public CustomRedisTokenStore tokenStore() {
        CustomRedisTokenStore redisTokenStore = new CustomRedisTokenStore(redisConnectionFactory, loginUtil, sessionRepository);
        redisTokenStore.setAuthenticationKeyGenerator(authenticationKeyGenerator());
        redisTokenStore.setPrefix(Constants.CacheKey.ACCESS_TOKEN);
        return redisTokenStore;
    }

    //
    // social config
    // ------------------------------------------------------------------------------

    @Bean
    @ConditionalOnMissingBean(SocialProviderRepository.class)
    public SocialProviderRepository socialProviderRepository() {
        return new CustomSocialProviderRepository();
    }

    @Bean
    @ConditionalOnMissingBean(SocialUserProviderRepository.class)
    public SocialUserProviderRepository socialUserProviderRepository() {
        return new CustomSocialUserProviderRepository();
    }

    @Bean
    @ConditionalOnMissingBean(SocialUserDetailsService.class)
    public SocialUserDetailsService socialUserDetailsService(UserAccountService userAccountService,
                                                             UserDetailsBuilder userDetailsBuilder,
                                                             LoginRecordService loginRecordService) {
        return new CustomSocialUserDetailsService(userAccountService, userDetailsBuilder, loginRecordService);
    }

    @Bean
    @ConditionalOnMissingBean(SocialAuthenticationProvider.class)
    public SocialAuthenticationProvider socialAuthenticationProvider(SocialUserProviderRepository socialUserProviderRepository,
                                                                     SocialUserDetailsService socialUserDetailsService) {
        return new CustomSocialAuthenticationProvider(socialUserProviderRepository, socialUserDetailsService);
    }

    @Bean
    @ConditionalOnMissingBean(SocialSuccessHandler.class)
    public SocialSuccessHandler socialSuccessHandler(SecurityProperties securityProperties,
                                                     List<LoginSuccessProcessor> successProcessors) {
        return new CustomSocialSuccessHandler(securityProperties, successProcessors);
    }

    @Bean
    @ConditionalOnMissingBean(CustomSocialFailureHandler.class)
    public CustomSocialFailureHandler socialFailureHandler(SecurityProperties securityProperties) {
        return new CustomSocialFailureHandler(securityProperties);
    }

}
