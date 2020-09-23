package org.hzero.oauth.security.oauth2.provider;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

/**
 * @author qingsheng.chen@hand-china.com
 */
public class ClientOAuth2Authentication extends OAuth2Authentication {

    /**
     * Construct an OAuth 2 authentication. Since some grant types don't require user authentication, the user
     * authentication may be null.
     *
     * @param storedRequest      The authorization request (must not be null).
     * @param userAuthentication The user authentication (possibly null).
     */
    public ClientOAuth2Authentication(OAuth2Request storedRequest, Authentication userAuthentication) {
        super(storedRequest, userAuthentication);
    }

    @Override
    public boolean isClientOnly() {
        return true;
    }
}
