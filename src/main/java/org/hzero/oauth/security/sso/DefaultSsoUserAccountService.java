package org.hzero.oauth.security.sso;

import static org.hzero.core.base.BaseConstants.Symbol.MIDDLE_LINE;
import static org.hzero.oauth.security.constant.LoginField.*;
import java.util.List;
import java.util.Set;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.util.Assert;

import org.hzero.core.user.UserType;
import org.hzero.core.util.Regexs;
import org.hzero.sso.core.domain.entity.SsoUser;
import org.hzero.oauth.domain.entity.User;
import org.hzero.oauth.domain.repository.UserRepository;
import org.hzero.oauth.security.config.SecurityProperties;
import org.hzero.sso.core.security.service.SsoUserAccountService;

/**
 * 单点登录业务默认实现
 *
 * @author hand 2020/01/13
 */
public class DefaultSsoUserAccountService implements SsoUserAccountService {

    private UserRepository userRepository;
    private Set<String> supportLoginFields;

    public DefaultSsoUserAccountService(UserRepository userRepository,
                                     SecurityProperties securityProperties) {
        this.userRepository = userRepository;
        supportLoginFields = securityProperties.getLogin().getSupportFields();
        Assert.isTrue(CollectionUtils.isNotEmpty(supportLoginFields), "support login fields must not be empty.");
    }

  


    @Override
    public SsoUser findLoginUser(String username, UserType userType) {
        return queryByLoginField(username, userType);
    }


    protected SsoUser queryByLoginField(String account, UserType userType) {
        if (StringUtils.isBlank(account)) {
            return null;
        }

        SsoUser user = new SsoUser();
        if (Regexs.isEmail(account) && supportLoginFields.contains(EMAIL.code())) {
            User dto = userRepository.selectLoginUserByEmail(account, userType);
            BeanUtils.copyProperties(dto,user);
        } else if (StringUtils.contains(account, MIDDLE_LINE) && supportLoginFields.contains(PHONE.code())) {
            String[] arr = StringUtils.split(account, MIDDLE_LINE, 2);
            String crownCode = arr[0];
            String mobile = arr[1];
            if (Regexs.isNumber(crownCode) && Regexs.isNumber(mobile) && Regexs.isMobile(crownCode, mobile)) {
            	User dto = userRepository.selectLoginUserByPhone(crownCode, mobile, userType);
            	BeanUtils.copyProperties(dto,user);
            }
        } else if (Regexs.isNumber(account) && Regexs.isMobile(account) && supportLoginFields.contains(PHONE.code())) {
        	User dto = userRepository.selectLoginUserByPhone(account, userType);
            BeanUtils.copyProperties(dto,user);
        }

        if (user.getLoginName() == null && supportLoginFields.contains(USERNAME.code())) {
        	User dto = userRepository.selectLoginUserByLoginName(account);
        	BeanUtils.copyProperties(dto,user);
        }
        return user;
    }

    @Override
    public List<Long> findUserLegalOrganization(Long userId) {
      return userRepository.findUserLegalOrganization(userId);
    }

    //
    // getter
    // ------------------------------------------------------------------------------

    protected UserRepository getUserRepository() {
        return userRepository;
    }

    protected Set<String> getSupportLoginFields() {
        return supportLoginFields;
    }
}
