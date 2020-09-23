package org.hzero.oauth.security.custom.processor.logout;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;

/**
 * 登出后置处理器
 *
 * @author xiaoyu.zhao@hand-china.com
 * @since 1.0
 */
@Component
public class LogoutLastProcessor implements LogoutSuccessProcessor {

    @Override
    public Object process(HttpServletRequest request, HttpServletResponse response) {
        return null;
    }

    @Override
    public int getOrder() {
        return Integer.MAX_VALUE;
    }
}
