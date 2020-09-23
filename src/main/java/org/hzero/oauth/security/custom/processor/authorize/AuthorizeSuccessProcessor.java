package org.hzero.oauth.security.custom.processor.authorize;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;

import org.hzero.oauth.security.custom.processor.Processor;

/**
 * 创建 token 后的处理器
 *
 * @author bojiangzhou 2019/11/20
 */
public interface AuthorizeSuccessProcessor extends Processor {

    @Override
    default Object process(HttpServletRequest request, HttpServletResponse response) {
        return null;
    }

    Object process(HttpServletRequest request, HttpServletResponse response, AuthorizationRequest authorizationRequest, OAuth2AccessToken accessToken);

}
