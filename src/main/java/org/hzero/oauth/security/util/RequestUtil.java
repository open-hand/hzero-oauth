package org.hzero.oauth.security.util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.choerodon.core.convertor.ApplicationContextHelper;

import org.hzero.oauth.security.config.SecurityProperties;
import org.hzero.oauth.security.constant.SecurityAttributes;

/**
 * 从 Request 中获取请求的默认值
 *
 * @author bojiangzhou 2019/05/24
 */
public class RequestUtil {


    public static HttpServletRequest getHttpServletRequest() {
        return ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
    }

    public static String getParameterValueFromRequestOrSavedRequest(String parameterName, String defaultValue) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        return getParameterValueFromRequestOrSavedRequest(request, parameterName, defaultValue);
    }

    /**
     * 获取请求中的参数，默认从 request 中获取，获取不到从 session 中保存的 request 中获取
     * 
     * @param request HttpServletRequest
     * @param parameterName 参数名称
     * @param defaultValue 默认值
     * @return 参数值
     */
    public static String getParameterValueFromRequestOrSavedRequest(HttpServletRequest request, String parameterName, String defaultValue) {
        String parameterValue = request.getParameter(parameterName);
        if (StringUtils.isNotBlank(parameterValue)) {
            return parameterValue;
        }
        HttpSession session = request.getSession(false);
        if (session == null) {
            return defaultValue;
        }
        DefaultSavedRequest saveRequest = (DefaultSavedRequest) session.getAttribute(SecurityAttributes.SECURITY_SAVED_REQUEST);
        if (saveRequest != null) {
            String[] values = saveRequest.getParameterValues(parameterName);
            if (values != null) {
                parameterValue = StringUtils.defaultIfBlank(values[0], defaultValue);
            }
        }
        parameterValue = StringUtils.defaultIfBlank(parameterValue, defaultValue);
        return parameterValue;
    }


    /**
     * 获取请求中的参数，默认从 request 中获取，获取不到从 session 中获取
     *
     * @param request HttpServletRequest
     * @param parameterName 参数名称
     * @param defaultValue 默认值
     * @return 参数值
     */
    public static String getParameterValueFromRequestOrSession(HttpServletRequest request, String parameterName, String defaultValue) {
        String parameterValue = request.getParameter(parameterName);
        if (StringUtils.isNotBlank(parameterValue)) {
            return parameterValue;
        }
        HttpSession session = request.getSession(false);
        if (session == null) {
            return defaultValue;
        }
        if (session.getAttribute(parameterName) != null) {
            parameterValue = (String) session.getAttribute(parameterName);
        }
        parameterValue = StringUtils.defaultIfBlank(parameterValue, defaultValue);
        return parameterValue;
    }

    private static String baseURL;

    public static String getOauthRootURL(HttpServletRequest request) {
        if (baseURL == null) {
            synchronized (RequestUtil.class) {
                SecurityProperties properties = ApplicationContextHelper.getContext().getBean(SecurityProperties.class);
                baseURL = properties.getBaseUrl();
            }
        }

        return baseURL;
    }

}
