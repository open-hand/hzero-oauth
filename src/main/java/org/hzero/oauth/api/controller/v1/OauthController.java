package org.hzero.oauth.api.controller.v1;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.http.ResponseEntity;
import org.springframework.social.connect.Connection;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import org.hzero.boot.oauth.domain.entity.BaseOpenApp;
import org.hzero.core.base.BaseConstants;
import org.hzero.core.user.UserType;
import org.hzero.core.util.Results;
import org.hzero.oauth.api.dto.Result;
import org.hzero.oauth.config.MultiLanguageConfig;
import org.hzero.oauth.domain.entity.Language;
import org.hzero.oauth.domain.entity.User;
import org.hzero.oauth.domain.service.LanguageService;
import org.hzero.oauth.domain.service.UserLoginService;
import org.hzero.oauth.domain.utils.ConfigGetter;
import org.hzero.oauth.domain.utils.ProfileCode;
import org.hzero.oauth.infra.encrypt.EncryptClient;
import org.hzero.oauth.security.config.SecurityProperties;
import org.hzero.oauth.security.constant.LoginType;
import org.hzero.oauth.security.constant.SecurityAttributes;
import org.hzero.oauth.security.util.LoginUtil;
import org.hzero.oauth.security.util.RequestUtil;
import org.hzero.starter.social.core.security.ProviderBindHelper;


/**
 * @author bojiangzhou
 */
@RefreshScope
@Controller
public class OauthController {

    private static final String LOGIN_DEFAULT = "login";
    private static final String LOGIN_MOBILE = "login-mobile";
    private static final String PASS_EXPIRED_PAGE = "pass-expired";
    private static final String PASS_FORCE_MODIFY_PAGE = "pass-force-modify";
    private static final String OPEN_BIND_PAGE = "open-app-bind";
    private static final String SLASH = BaseConstants.Symbol.SLASH;

    @Autowired
    private MultiLanguageConfig multiLanguageConfig;

    @Value("${hzero.oauth.redirect-url:login}")
    private String defaultUrl;

    private final UserLoginService userLoginService;
    private final LanguageService languageService;
    private final ConfigGetter configGetter;
    private final SecurityProperties securityProperties;
    private final EncryptClient encryptClient;


    public OauthController(UserLoginService userLoginService,
                           SecurityProperties securityProperties,
                           LanguageService languageService,
                           ConfigGetter configGetter,
                           EncryptClient encryptClient) {
        this.userLoginService = userLoginService;
        this.languageService = languageService;
        this.configGetter = configGetter;
        this.securityProperties = securityProperties;
        this.encryptClient = encryptClient;
    }

    @GetMapping(value = "/")
    public String index(HttpSession session, Model model) {
        String template = (String) session.getAttribute(LoginUtil.FIELD_TEMPLATE);
        template = StringUtils.defaultIfBlank(template, configGetter.getValue(ProfileCode.OAUTH_DEFAULT_TEMPLATE));
        model.addAttribute(LoginUtil.FIELD_TEMPLATE, template);
        return template + SLASH + defaultUrl;
    }

    @GetMapping("/public/{template}/{view}")
    public String renderView(HttpServletRequest request,HttpSession session, @PathVariable String template, @PathVariable String view, Model model) {
        Map<String, String[]> params = request.getParameterMap();
        if (MapUtils.isNotEmpty(params)) {
            params.forEach((key, value) -> {
                model.addAttribute(key, value[0]);
            });
        }
        // 设置多语言
        String lang = (String) session.getAttribute(SecurityAttributes.FIELD_LANG);
        setFindPwdPageLabel(model,lang);
        return template + SLASH + view;
    }

    /**
     * 默认登录页面
     */
    @GetMapping(value = "/login")
    public String login(HttpServletRequest request, Model model, HttpSession session,
                        @RequestParam(required = false) String device,
                        @RequestParam(required = false) String type) throws JsonProcessingException {
        setPageDefaultData(request, session, model);
        String template = (String) session.getAttribute(LoginUtil.FIELD_TEMPLATE);
        // 登录页面
        String returnPage = "mobile".equals(device) ? LOGIN_MOBILE : LOGIN_DEFAULT;
        returnPage = template + SLASH + returnPage;

        // 登录方式
        type = LoginType.match(type) != null ? type : SecurityAttributes.DEFAULT_LOGIN_TYPE.code();
        model.addAttribute(SecurityAttributes.FIELD_LOGIN_TYPE, type);

        User user = userLoginService.queryRequestUser(request);
        // 是否需要验证码
        model.addAttribute(SecurityAttributes.FIELD_IS_NEED_CAPTCHA, userLoginService.isNeedCaptcha(user));

        // 错误消息
        String exceptionMessage = (String) session.getAttribute(SecurityAttributes.SECURITY_LAST_EXCEPTION);
        if (StringUtils.isNotBlank(exceptionMessage)) {
            model.addAttribute(SecurityAttributes.FIELD_LOGIN_ERROR_MSG, exceptionMessage);
        }

        String username = (String) session.getAttribute(SecurityAttributes.SECURITY_LOGIN_USERNAME);

        SecurityAttributes.removeSecuritySessionAttribute(session);
        if (StringUtils.isBlank(username)) {
            return returnPage;
        }

        model.addAttribute(SecurityAttributes.SECURITY_LOGIN_USERNAME, username);
        if (LoginType.SMS.code().equals(type)) {
            model.addAttribute(SecurityAttributes.SECURITY_LOGIN_MOBILE, username);
        }

        return returnPage;
    }

    /**
     * 密码过期页面
     */
    @GetMapping(value = "/pass-page/expired")
    public String passExpired(HttpServletRequest request, Model model, HttpSession session) {
        // 模板
        String template = RequestUtil.getParameterValueFromRequestOrSavedRequest(request, LoginUtil.FIELD_TEMPLATE,
                configGetter.getValue(ProfileCode.OAUTH_DEFAULT_TEMPLATE));
        setLoginPageLabel(model, session);

        SecurityAttributes.removeSecuritySessionAttribute(session);

        return template + SLASH + PASS_EXPIRED_PAGE;
    }

    /**
     * 强制修改初始密码页面
     */
    @GetMapping(value = "/pass-page/force-modify")
    public String passForceModify(HttpServletRequest request, Model model, HttpSession session) {

        // 添加参数
        setLoginPageLabel(model, session);
        // 模板
        String template = RequestUtil.getParameterValueFromRequestOrSavedRequest(request, LoginUtil.FIELD_TEMPLATE,
                configGetter.getValue(ProfileCode.OAUTH_DEFAULT_TEMPLATE));

        SecurityAttributes.removeSecuritySessionAttribute(session);

        return template + SLASH + PASS_FORCE_MODIFY_PAGE;
    }

    private void setPageDefaultData(HttpServletRequest request, HttpSession session, Model model) throws JsonProcessingException {
        // 模板
        String template = RequestUtil.getParameterValueFromRequestOrSavedRequest(request, LoginUtil.FIELD_TEMPLATE, configGetter.getValue(ProfileCode.OAUTH_DEFAULT_TEMPLATE));
        // 控制用户类型
        String userType = RequestUtil.getParameterValueFromRequestOrSavedRequest(request, UserType.PARAM_NAME, UserType.DEFAULT_USER_TYPE);
        // 控制登录字段
        String loginField = RequestUtil.getParameterValueFromRequestOrSavedRequest(request, LoginUtil.FIELD_LOGIN_FIELD, null);

        model.addAttribute(LoginUtil.FIELD_TEMPLATE, template);

        session.setAttribute(LoginUtil.FIELD_TEMPLATE, template);
        session.setAttribute(UserType.PARAM_NAME, userType);
        session.setAttribute(LoginUtil.FIELD_LOGIN_FIELD, loginField);

        // 是否加密
        if (securityProperties.getPassword().isEnableEncrypt()) {
            String publicKey = encryptClient.getPublicKey();
            model.addAttribute(LoginUtil.FIELD_PUBLIC_KEY, publicKey);
            session.setAttribute(LoginUtil.FIELD_PUBLIC_KEY, publicKey);
        }
        setCommonPageConfigData(model);
        // 三方登录方式
        List<BaseOpenApp> apps = userLoginService.queryOpenLoginWays(request);
        model.addAttribute(SecurityAttributes.FIELD_OPEN_LOGIN_WAYS, apps);
        model.addAttribute(SecurityAttributes.FIELD_OPEN_LOGIN_WAYS_JSON, BaseConstants.MAPPER.writeValueAsString(apps));
        // 语言
        if (configGetter.isTrue(ProfileCode.OAUTH_SHOW_LANGUAGE)) {
            List<Language> languages = languageService.listLanguage();
            model.addAttribute(SecurityAttributes.FIELD_LANGUAGES, languages);
            model.addAttribute(SecurityAttributes.FIELD_LANGUAGES_JSON, BaseConstants.MAPPER.writeValueAsString(languages));
        }

        setLoginPageLabel(model, session);
    }

    /**
     *  设置通用的页面配置参数
     */
    private void setCommonPageConfigData(Model model) {
        // 页面标题
        model.addAttribute(LoginUtil.FIELD_TITLE, configGetter.getValue(ProfileCode.OAUTH_TITLE));
        // Logo 地址
        model.addAttribute(LoginUtil.FIELD_LOGO_URL, configGetter.getValue(ProfileCode.OAUTH_LOGO_URL));
        // copyright
        model.addAttribute(LoginUtil.FIELD_COPYRIGHT, configGetter.getValue(ProfileCode.OAUTH_COPYRIGHT));
    }

    /**
     * 跳转到绑定账号页面
     */
    @GetMapping(value = "/open-bind")
    public String bind(HttpServletRequest request, Model model, HttpSession session) throws JsonProcessingException {
        Connection<?> connection = ProviderBindHelper.getConnection(request);
        if (connection == null) {
            return "redirect:login";
        }
        setPageDefaultData(request, session, model);

        String template = (String) session.getAttribute(LoginUtil.FIELD_TEMPLATE);

        return template + SLASH + OPEN_BIND_PAGE;
    }

    //
    // /api/user
    // ------------------------------------------------------------------------------

    @ResponseBody
    @RequestMapping("/api/user")
    public Principal user(Principal principal) {
        return principal;
    }

    /**
     * 查询登录语言
     */
    @GetMapping(value = "/login/lang")
    public ResponseEntity<Result> listLang(){
        Result result = new Result(true);
        if (configGetter.isTrue(ProfileCode.OAUTH_SHOW_LANGUAGE)) {
            result.setData(languageService.listLanguage());
        } else {
            result.setData(Collections.emptyList());
        }
        return Results.success(result);
    }

    /**
     * 设置登录语言
     */
    @PostMapping(value = "/login/lang")
    public ResponseEntity<Result> saveLang(HttpSession session,@RequestParam(required = false) String lang){
        session.removeAttribute(SecurityAttributes.FIELD_LANG);
        lang = checkLang(lang);
        session.setAttribute(SecurityAttributes.FIELD_LANG, lang);
        return Results.success(new Result(true));
    }

    /**
     * 设置登录页面多语言标签
     */
    private void setLoginPageLabel(Model model, HttpSession session) {
        // 默认语言
        String language = (String) session.getAttribute(SecurityAttributes.FIELD_LANG);
        if (StringUtils.isBlank(language)) {
            language = configGetter.getValue(ProfileCode.OAUTH_DEFAULT_LANGUAGE);
            model.addAttribute(SecurityAttributes.FIELD_LANG, language);
        }
        Map<String, String> map =  multiLanguageConfig.getLanguageValue(language);
        model.addAllAttributes(map);
    }

    private void setFindPwdPageLabel(Model model, String lang) {
        Map<String, String> map =  multiLanguageConfig.getLanguageValue(lang);
        model.addAllAttributes(map);
        setCommonPageConfigData(model);
    }

    /**
     * 获取Locale
     */
    private String checkLang(String lang) {
        if(StringUtils.isBlank(lang) || !lang.contains(BaseConstants.Symbol.LOWER_LINE)){
            return configGetter.getValue(ProfileCode.OAUTH_DEFAULT_LANGUAGE);
        }
        return lang;
    }

}
