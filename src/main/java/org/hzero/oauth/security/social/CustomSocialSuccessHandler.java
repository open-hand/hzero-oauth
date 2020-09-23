package org.hzero.oauth.security.social;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import javax.annotation.PostConstruct;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;

import org.hzero.oauth.security.config.SecurityProperties;
import org.hzero.oauth.security.custom.processor.Processor;
import org.hzero.oauth.security.custom.processor.login.LoginSuccessProcessor;
import org.hzero.starter.social.core.security.SocialSuccessHandler;

/**
 * 登录成功处理器
 *
 * @author bojiangzhou 2019/02/25
 */
public class CustomSocialSuccessHandler extends SocialSuccessHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomSocialSuccessHandler.class);

    private SecurityProperties securityProperties;

    private List<LoginSuccessProcessor> successProcessors = new ArrayList<>();

    public CustomSocialSuccessHandler(SecurityProperties securityProperties,
                                      List<LoginSuccessProcessor> successProcessors) {
        this.securityProperties = securityProperties;
        this.successProcessors.addAll(successProcessors);
    }

    @PostConstruct
    private void init() {
        this.setDefaultTargetUrl(securityProperties.getLogin().getSuccessUrl());
        successProcessors.sort(Comparator.comparingInt(Processor::getOrder));
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        for (LoginSuccessProcessor processor : successProcessors) {
            try {
                processor.process(request, response);
            } catch (Exception e) {
                LOGGER.error("success processor error, processor is {}, ex={}",
                        processor.getClass().getSimpleName(), e.getMessage(), e);
            }
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }

    protected SecurityProperties getSecurityProperties() {
        return securityProperties;
    }
}


