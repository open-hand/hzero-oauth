package org.hzero.oauth.security.custom.processor.logout;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.hzero.oauth.domain.service.AuditLoginService;
import org.hzero.oauth.security.service.LoginRecordService;

/**
 * 登出审计
 *
 * @author XCXCXCXCX
 * @since 1.0
 */
@Component
public class LogoutAuditProcessor implements LogoutSuccessProcessor {

    @Autowired
    private AuditLoginService auditLoginService;
    @Autowired
    private LoginRecordService loginRecordService;

    @Override
    public Object process(HttpServletRequest request, HttpServletResponse response) {
        auditLoginService.addLogOutRecord(request, loginRecordService.getLocalLoginUser());
        return null;
    }

    @Override
    public int getOrder() {
        return 0;
    }


}
