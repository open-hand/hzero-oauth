package org.hzero.oauth.security.custom.processor.logout;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;

import org.hzero.core.util.TokenUtils;
import org.hzero.oauth.security.config.SecurityProperties;
import org.hzero.sso.core.custom.processor.cas.logout.CasLogoutProcessor;

/**
 * 清除 token
 *
 * @author bojiangzhou 2019/11/20
 */
@Component
public class ClearTokenProcessor implements LogoutSuccessProcessor, CasLogoutProcessor {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClearTokenProcessor.class);

    @Autowired
    private SecurityProperties securityProperties;
    @Autowired
    private TokenStore tokenStore;

    @Override
    public Object process(HttpServletRequest request, HttpServletResponse response) {
        String token = TokenUtils.getToken(request);

        if (securityProperties.getLogout().isClearToken()) {
            request.getSession().invalidate();
            if (token != null) {
                LOGGER.debug("logout clear access token :{} ", token);
                tokenStore.removeAccessToken(new DefaultOAuth2AccessToken(token));
                tokenStore.removeRefreshToken(new DefaultOAuth2RefreshToken(token));
            }
        }
        String logoutUrl = (String) request.getAttribute("CAS_LOGOUT_URL");
        if (StringUtils.isNotBlank(logoutUrl)) {
            LOGGER.debug("sso cas logout, tlogoutUrl:[{}]", logoutUrl);
            try {
                response.sendRedirect(logoutUrl);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public int getOrder() {
        return 100;
    }


}
