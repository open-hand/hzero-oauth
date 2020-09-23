package org.hzero.oauth.security.service.impl;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.choerodon.core.oauth.CustomUserDetails;

import org.hzero.boot.oauth.domain.entity.BaseClient;
import org.hzero.oauth.domain.entity.User;
import org.hzero.oauth.security.service.UserAccountService;
import org.hzero.oauth.security.service.UserDetailsBuilder;
import org.hzero.oauth.security.service.UserDetailsWrapper;
import org.hzero.oauth.security.util.RequestUtil;
import org.hzero.sso.core.config.SsoAuthenticationEntryPoint;
import org.hzero.sso.core.config.SsoProperties;
import org.hzero.sso.core.domain.entity.Domain;
import org.hzero.sso.core.domain.repository.DomainRepository;

/**
 * 构建 CustomUserDetails
 *
 * @author bojiangzhou 2019/07/24
 */
public class DefaultUserDetailsBuilder implements UserDetailsBuilder {
    private static final String LANG = "lang";

    private final UserDetailsWrapper userDetailsWrapper;
    private final DomainRepository domainRepository;
    private final SsoProperties ssoProperties;
    private final UserAccountService userAccountService;

    public DefaultUserDetailsBuilder(UserDetailsWrapper userDetailsWrapper,
                                     DomainRepository domainRepository,
                                     SsoProperties ssoProperties,
                                     UserAccountService userAccountService) {
        this.userDetailsWrapper = userDetailsWrapper;
        this.domainRepository = domainRepository;
        this.ssoProperties = ssoProperties;
        this.userAccountService = userAccountService;
    }

    @Override
    public CustomUserDetails buildUserDetails(User user) {
        CustomUserDetails details = new CustomUserDetails(user.getLoginName(), user.getPassword(), user.getUserType(), Collections.emptyList());
        details.setUserId(user.getId());
        details.setLanguage(Optional.ofNullable(getLanguageFromSession()).orElse(user.getLanguage()));
        details.setTimeZone(user.getTimeZone());
        details.setEmail(user.getEmail());
        details.setOrganizationId(user.getOrganizationId());
        details.setAdmin(user.getAdmin());
        details.setRealName(user.getRealName());
        details.setImageUrl(user.getImageUrl());

        BaseClient client = userAccountService.findCurrentClient();
        if (client != null) {
            // 接口加密标识
            details.setApiEncryptFlag(client.getApiEncryptFlag());
        }

        getUserDetailsWrapper().warp(details, user.getId(), Optional.ofNullable(getRequestTenantId()).orElse(user.getOrganizationId()), true);

        return details;
    }

    /**
     * 此方法实现逻辑：参考 {@link SsoAuthenticationEntryPoint} <i>getSsoDomain</i> 方法
     *
     * <pre>
     * 1.从请求参数或session报错的重定向地址中获取 redirect_uri 参数
     * 2.根据 redirect_uri 获取二级域名
     * 3.返回二级域名对应的租户
     * </pre>
     *
     * @return 从请求中获取当前租户
     * @see SsoAuthenticationEntryPoint
     */
    protected Long getRequestTenantId() {
        if (domainRepository == null || ssoProperties == null || disableSso()) {
            return null;
        }

        String redirectUrl = RequestUtil.getParameterValueFromRequestOrSavedRequest(OAuth2Utils.REDIRECT_URI, null);
        if (StringUtils.isEmpty(redirectUrl)) {
            return null;
        }

        String redirectUri;
        try {
            URL url = new URL(redirectUrl);
            if (url.getPort() > 0) {
                redirectUri = url.getHost() + ":" + url.getPort();
            } else {
                redirectUri = url.getHost();
            }
        } catch (MalformedURLException e) {
            return null;
        }
        if (StringUtils.isEmpty(redirectUri)) {
            return null;
        }
        List<Domain> domains = domainRepository.selectAllDomain();
        if (domains == null || domains.size() == 0) {
            return null;
        }

        String finalRedirectUri = redirectUri;
        Domain domain = domains.stream()
                .filter(d -> d.getSsoTypeCode() != null && d.getDomainUrl().contains(finalRedirectUri))
                .findFirst()
                .orElse(null);

        if (domain != null) {
            return domain.getTenantId();
        }
        return null;
    }

    private boolean disableSso() {
        String disable = RequestUtil.getParameterValueFromRequestOrSavedRequest(ssoProperties.getSso().getDisableSsoParameter(), null);
        return !StringUtils.isEmpty(disable) && !("0".equals(disable) || "false".equals(disable));
    }

    private String getLanguageFromSession() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes instanceof ServletRequestAttributes) {
            HttpSession session = ((ServletRequestAttributes) requestAttributes).getRequest().getSession(false);
            if (session != null) {
                String attribute = (String) session.getAttribute(LANG);
                if (StringUtils.hasText(attribute)) {
                    return attribute;
                }
            }
        }
        return null;
    }

    public UserDetailsWrapper getUserDetailsWrapper() {
        return userDetailsWrapper;
    }
}
