package org.hzero.oauth.security.custom.processor.cas.login;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import org.hzero.sso.core.custom.processor.cas.login.CasLoginProcessor;
import org.hzero.sso.core.util.CasUtils;

/**
 * Cas 信息记录
 *
 * @author bojiangzhou 2019/11/21
 */
@Component
public class CasSignInProcessor implements CasLoginProcessor {

    private static final Logger LOGGER = LoggerFactory.getLogger(CasSignInProcessor.class);

    @Override
    public Object process(HttpServletRequest request, HttpServletResponse response) {
        final String ticket = request.getParameter("ticket");
        return process(request, response, ticket);
    }

    @Override
    public Object process(HttpServletRequest request, HttpServletResponse response, String ticket) {
        // 将 ticket 记录到 session 中
        if (StringUtils.isNotBlank(ticket)) {
            LOGGER.debug("Recording cas ticket: [{}]", ticket);
            request.getSession().setAttribute(CasUtils.ATTRIBUTE_CAS_TICKET, ticket);
        }
        return null;
    }

    @Override
    public int getOrder() {
        return 10;
    }
}
