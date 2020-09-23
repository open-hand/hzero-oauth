package org.hzero.oauth.domain.service.impl;

import org.hzero.boot.oauth.domain.service.UserPasswordService;
import org.hzero.core.captcha.CaptchaMessageHelper;
import org.hzero.core.captcha.CaptchaResult;
import org.hzero.core.exception.MessageException;
import org.hzero.core.user.UserType;
import org.hzero.oauth.domain.entity.User;
import org.hzero.oauth.domain.repository.UserRepository;
import org.hzero.oauth.domain.service.PasswordService;
import org.hzero.oauth.infra.constant.Constants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import io.choerodon.core.exception.CommonException;

/**
 * @author bojiangzhou 2019/03/04
 */
@Component
public class PasswordServiceImpl implements PasswordService {

    @Autowired
    private CaptchaMessageHelper captchaMessageHelper;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserPasswordService userPasswordService;

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void updatePasswordByAccount(String account, UserType userType, String businessScope,
                                        String password, String captchaKey, String captcha) {

        CaptchaResult captchaResult = captchaMessageHelper.checkCaptcha(captchaKey, captcha, account, userType,
                businessScope, Constants.APP_CODE, false);
        if (!captchaResult.isSuccess()) {
            throw new MessageException(captchaResult.getMessage(), captchaResult.getCode());
        }

        User user = userRepository.selectUserByPhoneOrEmail(account, userType);
        if (user == null) {
            throw new CommonException("hoth.warn.phoneOrEmailNotFound");
        }

        userPasswordService.updateUserPassword(user.getId(), password);
    }

    @Override
    public void updatePasswordByUser(Long userId, UserType userType, String password) {
        userPasswordService.updateUserPassword(userId, password);
    }

}
