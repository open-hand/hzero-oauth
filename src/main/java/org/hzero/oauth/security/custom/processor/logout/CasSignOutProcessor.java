package org.hzero.oauth.security.custom.processor.logout;

import static org.hzero.sso.core.util.CasUtils.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import org.hzero.core.redis.RedisHelper;
import org.hzero.core.util.TokenUtils;
import org.hzero.core.variable.RequestVariableHolder;
import org.hzero.sso.core.custom.processor.cas.logout.CasLogoutProcessor;

/**
 * Cas 信息记录
 *
 * @author bojiangzhou 2019/11/21
 */
@Component
public class CasSignOutProcessor implements CasLogoutProcessor, LogoutSuccessProcessor {
    private static final Logger LOGGER = LoggerFactory.getLogger(CasSignOutProcessor.class);

    @Autowired
    private RedisHelper redisHelper;
    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public Object process(HttpServletRequest request, HttpServletResponse response) {
        String ticket = (String) request.getAttribute(ATTRIBUTE_CAS_TICKET);
        String token = null;
        if (StringUtils.isNotBlank(ticket)) {
            token = redisHelper.strGet(KEY_CAS_TICKET_TOKEN + ticket);
        } else {
            token = TokenUtils.getToken(request);
            ticket = redisHelper.strGet(KEY_CAS_TOKEN_TICKET + token);
        }

        if (ticket == null) {
            return null;
        }

        String logoutUrl = redisHelper.strGet(KEY_TOKEN_LOGOUT_URL + token);
        LOGGER.debug("sso cas logout, ticket:[{}], token:[{}], logoutUrl:[{}]", ticket, token, logoutUrl);
        if (StringUtils.isNotBlank(logoutUrl)) {
            request.setAttribute("CAS_LOGOUT_URL", logoutUrl);
        }

        // 清除 token_ticket
        redisHelper.delKey(KEY_CAS_TOKEN_TICKET + token);
        // 清除 ticket_token
        redisHelper.delKey(KEY_CAS_TICKET_TOKEN + ticket);
        // 清除 token_logoutUrl
        redisHelper.delKey(KEY_TOKEN_LOGOUT_URL + token);

        request.setAttribute(RequestVariableHolder.ACCESS_TOKEN, token);
        return null;
    }

    @Override
    public int getOrder() {
        return 20;
    }


}
