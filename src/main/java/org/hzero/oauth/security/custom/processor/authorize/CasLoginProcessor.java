package org.hzero.oauth.security.custom.processor.authorize;


import static org.hzero.sso.core.util.CasUtils.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import org.hzero.core.redis.RedisHelper;
import org.hzero.oauth.security.util.RequestUtil;
import org.hzero.sso.core.domain.entity.Domain;
import org.hzero.sso.core.domain.repository.DomainRepository;

/**
 * 单点登录成功后，记录 ticket 和 access_token 关系，便于处理单点退出
 *
 * @author bojiangzhou 2019/11/20
 */
@Component
public class CasLoginProcessor implements AuthorizeSuccessProcessor {

    private static final Logger LOGGER = LoggerFactory.getLogger(CasLoginProcessor.class);

    @Autowired
    private RedisHelper redisHelper;
    @Autowired
    private DomainRepository domainRepository;

    @Override
    public Object process(HttpServletRequest request, HttpServletResponse response,
                          AuthorizationRequest authorizationRequest, OAuth2AccessToken accessToken) {

        HttpSession session = request.getSession(false);
        if (session != null && session.getAttribute(ATTRIBUTE_CAS_TICKET) != null) {
            String access_token = accessToken.getValue();
            String ticket = (String) session.getAttribute(ATTRIBUTE_CAS_TICKET);
            session.removeAttribute(ATTRIBUTE_CAS_TICKET);
            redisHelper.strSet(KEY_CAS_TICKET_TOKEN + ticket, access_token, 24, TimeUnit.HOURS);
            redisHelper.strSet(KEY_CAS_TOKEN_TICKET + access_token, ticket, 24, TimeUnit.HOURS);
            Domain domain = getSsoDomain(request, response);
            if (domain != null) {
                redisHelper.strSet(KEY_TOKEN_LOGOUT_URL + access_token, domain.getSsoLogoutUrl(), 24, TimeUnit.HOURS);
            }

            LOGGER.info("cas login, ticket is {}, access_token is {}", ticket, access_token);
        }

        return null;
    }

    @Override
    public int getOrder() {
        return 30;
    }

    protected Domain getSsoDomain(final HttpServletRequest request, final HttpServletResponse response) {
        String redirectUrl = RequestUtil.getParameterValueFromRequestOrSavedRequest(OAuth2Utils.REDIRECT_URI, null);
        if (org.springframework.util.StringUtils.isEmpty(redirectUrl)) {
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

        LOGGER.debug("sso cas domain, redirectUrl:[{}], redirectUri: [{}]", redirectUrl, redirectUri);

        if (StringUtils.isEmpty(redirectUri)) {
            return null;
        }
        List<Domain> domains = domainRepository.selectAllDomain();
        if (domains == null || domains.size() == 0) {
            return null;
        }

        String finalRedirectUri = redirectUri;
        return domains.stream()
                .filter(d -> d.getSsoTypeCode() != null && d.getDomainUrl().contains(finalRedirectUri))
                .findFirst()
                .orElse(null);
    }
}
