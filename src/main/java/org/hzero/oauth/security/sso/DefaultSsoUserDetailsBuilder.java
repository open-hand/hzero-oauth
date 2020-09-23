package org.hzero.oauth.security.sso;

import org.springframework.beans.BeanUtils;

import io.choerodon.core.oauth.CustomUserDetails;

import org.hzero.oauth.domain.entity.User;
import org.hzero.oauth.security.service.UserAccountService;
import org.hzero.oauth.security.service.UserDetailsWrapper;
import org.hzero.oauth.security.service.impl.DefaultUserDetailsBuilder;
import org.hzero.sso.core.config.SsoProperties;
import org.hzero.sso.core.domain.entity.SsoUser;
import org.hzero.sso.core.domain.repository.DomainRepository;
import org.hzero.sso.core.security.service.SsoUserDetailsBuilder;

/**
 * 构建 CustomUserDetails
 *
 * @author bojiangzhou 2019/07/24
 */
public class DefaultSsoUserDetailsBuilder extends DefaultUserDetailsBuilder implements SsoUserDetailsBuilder {

    public DefaultSsoUserDetailsBuilder(UserDetailsWrapper userDetailsWrapper,
                                        DomainRepository domainRepository,
                                        SsoProperties ssoProperties,
                                        UserAccountService userAccountService) {
        super(userDetailsWrapper, domainRepository, ssoProperties, userAccountService);
    }

    @Override
    public CustomUserDetails buildUserDetails(SsoUser ssoUser) {
        User user = new User();
        try {
            BeanUtils.copyProperties(ssoUser, user);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return super.buildUserDetails(user);
    }

}
