package org.hzero.oauth.security.custom;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Comparator;
import java.util.List;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import io.choerodon.core.oauth.CustomUserDetails;

import org.hzero.core.util.TokenUtils;
import org.hzero.oauth.domain.entity.User;
import org.hzero.sso.core.domain.repository.DomainRepository;
import org.hzero.sso.core.domain.entity.Domain;
import org.hzero.oauth.security.config.SecurityProperties;
import org.hzero.oauth.security.custom.processor.Processor;
import org.hzero.oauth.security.custom.processor.logout.LogoutSuccessProcessor;
import org.hzero.oauth.security.service.LoginRecordService;
import org.hzero.oauth.security.service.UserAccountService;
import org.hzero.sso.core.config.SsoProperties;

/**
 * 登出处理器
 *
 * @author bojiangzhou
 */
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomLogoutSuccessHandler.class);

    private TokenStore tokenStore;
    private LoginRecordService loginRecordService;
    private SecurityProperties securityProperties;
    private SsoProperties ssoProperties;
    private DomainRepository domainRepository;
    private UserAccountService userAccountService;
    private List<LogoutSuccessProcessor> logoutProcessors;

    public CustomLogoutSuccessHandler(TokenStore tokenStore,
                                      LoginRecordService loginRecordService,
                                      SecurityProperties securityProperties,
                                      SsoProperties ssoProperties,
                                      DomainRepository domainRepository,
                                      UserAccountService userAccountService,
                                      List<LogoutSuccessProcessor> logoutProcessors) {
        this.tokenStore = tokenStore;
        this.loginRecordService = loginRecordService;
        this.securityProperties = securityProperties;
        this.domainRepository = domainRepository;
        this.logoutProcessors = logoutProcessors;
        this.userAccountService = userAccountService;
        this.ssoProperties = ssoProperties;
    }

    @PostConstruct
    private void init() {
        logoutProcessors.sort(Comparator.comparingInt(Processor::getOrder));
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
                    throws IOException {
        String token = TokenUtils.getToken(request);

        // 退出地址
        String logoutUrl = loginRecordService.getLogoutUrl(token);
        if (StringUtils.isBlank(logoutUrl)) {
            if (ssoProperties.getSso().isEnabled() && domainRepository != null) {
                logoutUrl = getLogoutUrl(logoutUrl);
            }
            if (StringUtils.isBlank(logoutUrl)) {
                String referer = request.getHeader("Referer");
                if (referer != null) {
                    logoutUrl = referer;
                } else {
                    logoutUrl = securityProperties.getLogin().getSuccessUrl();
                }
            }
        }


        LOGGER.debug("logout info, token={}, logoutUrl={}", token, logoutUrl);

        if (authentication == null) {
            authentication = tokenStore.readAuthentication(token);
        }
        if (authentication == null) {
            LOGGER.warn("logout user not found. token={}", token);
            response.sendRedirect(logoutUrl);
            return;
        }

        // 查询登出用户
        Object principal = authentication.getPrincipal();
        if (principal instanceof CustomUserDetails) {
            CustomUserDetails details = (CustomUserDetails) principal;
            User logoutUser = userAccountService.findLoginUser(details.getUserId());
            loginRecordService.saveLocalLoginUser(logoutUser);
        }

        // 处理器处理
        for (LogoutSuccessProcessor processor : logoutProcessors) {
            try {
                processor.process(request, response);
            } catch (Exception e) {
                LOGGER.error("logout processor error, processor is {}, ex={}",
                        processor.getClass().getSimpleName(), e.getMessage(), e);
            }
        }

        response.sendRedirect(logoutUrl);
    }
    
    /**
     * 根据请求获取域名信息
     */
    protected String getLogoutUrl(String referer) {
        java.net.URL url;
        try {
            url = new  java.net.URL(referer);
        } catch (MalformedURLException e) {
            return referer;
        }
        String redirectUri = url.getHost();
        if(StringUtils.isBlank(redirectUri)){
            return referer;
        }
        // 查询域名
        List<Domain> domains = domainRepository.selectAllDomain();
        if(domains == null || domains.size() == 0){
            return referer;
        }
        Domain selectDomain = domains.stream().filter(d -> d.getSsoTypeCode() != null && d.getDomainUrl().contains(redirectUri)).findFirst().orElse(null);
        if(selectDomain == null || selectDomain.getSsoLogoutUrl() == null ){
            return referer; 
        }else{
            return selectDomain.getSsoLogoutUrl();
        }
    }

    protected TokenStore getTokenStore() {
        return tokenStore;
    }

    protected LoginRecordService getLoginRecordService() {
        return loginRecordService;
    }

    protected SecurityProperties getSecurityProperties() {
        return securityProperties;
    }
}
