package org.hzero.oauth.security.custom.processor.authorize;

import java.util.concurrent.TimeUnit;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Component;

import org.hzero.core.redis.RedisHelper;
import org.hzero.oauth.security.service.LoginRecordService;

/**
 * 创建 access_token 之后，记录登出地址
 *
 * @author bojiangzhou 2019/11/20
 */
@Component
public class RecordLogoutUrlProcessor implements AuthorizeSuccessProcessor {

    @Autowired
    private RedisHelper redisHelper;

    @Override
    public Object process(HttpServletRequest request, HttpServletResponse response,
                          AuthorizationRequest authorizationRequest, OAuth2AccessToken accessToken) {

        String logoutRedirectUrl = request.getParameter("redirect_uri");
        if (!StringUtils.isEmpty(logoutRedirectUrl)) {
            redisHelper.strSet(LoginRecordService.LOGOUT_REDIRECT_URL_PREFIX + accessToken.getValue(), logoutRedirectUrl, 24, TimeUnit.HOURS);
        }

        return null;
    }

    @Override
    public int getOrder() {
        return 10;
    }
}
