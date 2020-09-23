package org.hzero.oauth.api.controller.v1;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.hzero.common.HZeroService;
import org.hzero.core.base.BaseConstants;
import org.hzero.core.captcha.CaptchaImageHelper;
import org.hzero.core.captcha.CaptchaResult;
import org.hzero.core.message.MessageAccessor;
import org.hzero.core.user.UserType;
import org.hzero.core.util.Results;
import org.hzero.oauth.domain.service.UserLoginService;
import org.hzero.oauth.domain.vo.AuthenticationResult;
import org.hzero.oauth.security.exception.CustomAuthenticationException;
import org.hzero.oauth.security.exception.ErrorWithTimesException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * 登录接口
 *
 * @author bojiangzhou 2019/06/01
 */
@RestController
public class LoginController {

    @Autowired
    private CaptchaImageHelper captchaImageHelper;
    @Autowired
    private UserLoginService userLoginService;

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginController.class);

    @ApiOperation(value = "获取图片验证码 - 输出验证码图片")
    @GetMapping("/public/captcha")
    public void createCaptcha(HttpServletResponse response) {
        captchaImageHelper.generateAndWriteCaptchaImage(response, HZeroService.Oauth.CODE);
    }

    @ApiOperation(value = "获取验证码Key")
    @GetMapping("/public/captcha-code")
    @ResponseBody
    public ResponseEntity<CaptchaResult> createCaptchaCode() {
        CaptchaResult captchaResult = captchaImageHelper.generateCaptcha(HZeroService.Oauth.CODE);
        captchaResult.setCaptcha(null);
        return Results.success(captchaResult);
    }

    @ApiOperation(value = "通过captchaKey获取图片验证码 - 输出验证码图片")
    @GetMapping("/public/captcha/{captchaKey}")
    public void createCaptcha(@PathVariable String captchaKey, HttpServletResponse response) {
        captchaImageHelper.generateAndWriteCaptchaImage(response, captchaKey, HZeroService.Oauth.CODE);
    }

    /**
     * 发送手机验证码(校验手机号是否注册)
     */
    @GetMapping("/public/send-phone-captcha")
    @ResponseBody
    public ResponseEntity<CaptchaResult> sendPhoneCaptcha(
            @RequestParam(defaultValue = BaseConstants.DEFAULT_CROWN_CODE) String internationalTelCode,
            @RequestParam("phone") String phone,
            @RequestParam(name = UserType.PARAM_NAME, required = false, defaultValue = UserType.DEFAULT_USER_TYPE) String userType,
            @RequestParam(required = false) String businessScope) {
        CaptchaResult captchaResult = userLoginService.sendPhoneCaptcha(internationalTelCode, phone,
                UserType.ofDefault(userType), businessScope, true);

        return Results.success(captchaResult);
    }

    /**
     * 发送手机验证码(不校验手机号是否注册)
     */
    @PostMapping("/public/send-phone-captcha-always")
    @ResponseBody
    public ResponseEntity<CaptchaResult> sendPhoneCaptchaNotCheckRegistered(
            @ApiParam("国际冠码，默认+86") @RequestParam(defaultValue = BaseConstants.DEFAULT_CROWN_CODE) String internationalTelCode,
            @RequestParam("phone") String phone,
            @RequestParam(name = UserType.PARAM_NAME, required = false, defaultValue = UserType.DEFAULT_USER_TYPE) String userType,
            @RequestParam(required = false) String businessScope) {
        CaptchaResult captchaResult = userLoginService.sendPhoneCaptcha(internationalTelCode, phone,
                UserType.ofDefault(userType), businessScope, false);

        return Results.success(captchaResult);
    }

    @ApiOperation("获取登录初始化参数，包含三方登录方式")
    @GetMapping("/login/init-params")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getLoginInitParams(HttpServletRequest request) {
        return Results.success(userLoginService.getLoginInitParams(request));
    }

    @ApiOperation("手机+验证码，返回Token(移动端)")
    @PostMapping("/token/mobile")
    @ResponseBody
    public ResponseEntity<AuthenticationResult> loginMobileToken(HttpServletRequest request) {
        AuthenticationResult authenticationResult = null;
        try {
            authenticationResult = userLoginService.loginMobileForToken(request);
        } catch (ErrorWithTimesException e) {
            LOGGER.warn("login for token error, ex={}", e.getMessage());
            authenticationResult = new AuthenticationResult(false,
                    e.getMessage(), MessageAccessor.getMessage(e.getMessage(), e.getParameters()).desc());
            authenticationResult.setErrorTimes(e.getErrorTimes());
            authenticationResult.setSurplusTimes(e.getSurplusTimes());
        } catch (CustomAuthenticationException e) {
            LOGGER.warn("login for token error, ex={}", e.getMessage());
            authenticationResult = new AuthenticationResult(false,
                    e.getMessage(), MessageAccessor.getMessage(e.getMessage(), e.getParameters()).desc());
        } catch (Exception e) {
            LOGGER.warn("login for token error, ex={}", e.getMessage());
            authenticationResult = new AuthenticationResult(false,
                    e.getMessage(), MessageAccessor.getMessage(e.getMessage()).desc());
        }

        return Results.success(authenticationResult);
    }

    @ApiOperation("绑定三方账号(移动端)")
    @PostMapping("/open-bind")
    @ResponseBody
    public ResponseEntity<AuthenticationResult> bindOpenAccount(HttpServletRequest request) {
        AuthenticationResult authenticationResult = null;
        try {
            authenticationResult = userLoginService.bindOpenAccount(request);
        } catch (CustomAuthenticationException e) {
            LOGGER.warn("login for token error, ex={}", e.getMessage());
            authenticationResult = new AuthenticationResult(false, e.getMessage(), MessageAccessor.getMessage(e.getMessage(), e.getParameters()).desc());
        } catch (Exception e) {
            LOGGER.warn("login for token error, ex={}", e.getMessage());
            authenticationResult = new AuthenticationResult(false, e.getMessage(), MessageAccessor.getMessage(e.getMessage()).desc());
        }

        return Results.success(authenticationResult);
    }

    @ApiOperation("三方openId登录，返回Token(移动端)")
    @PostMapping("/token/open")
    @ResponseBody
    public ResponseEntity<AuthenticationResult> loginOpenToken(HttpServletRequest request) {
        AuthenticationResult authenticationResult = null;
        try {
            authenticationResult = userLoginService.loginOpenForToken(request);
        } catch (CustomAuthenticationException e) {
            LOGGER.warn("login for token error, ex={}", e.getMessage());
            authenticationResult = new AuthenticationResult(false, e.getMessage(), MessageAccessor.getMessage(e.getMessage(), e.getParameters()).desc());
        } catch (Exception e) {
            LOGGER.warn("login for token error, ex={}", e.getMessage());
            authenticationResult = new AuthenticationResult(false, e.getMessage(), MessageAccessor.getMessage(e.getMessage()).desc());
        }

        return Results.success(authenticationResult);
    }

}
