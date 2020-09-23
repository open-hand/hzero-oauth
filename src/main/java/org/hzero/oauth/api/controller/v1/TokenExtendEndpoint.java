package org.hzero.oauth.api.controller.v1;

import io.choerodon.core.oauth.CustomUserDetails;
import org.hzero.oauth.domain.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

/**
 * @author XCXCXCXCX
 * @since 1.0
 */
@FrameworkEndpoint
public class TokenExtendEndpoint {

    private final TokenEndpoint tokenEndpoint;

    private final TokenStore tokenStore;

    private final UserRepository userRepository;

    public TokenExtendEndpoint(TokenEndpoint tokenEndpoint, TokenStore tokenStore, UserRepository userRepository) {
        this.tokenEndpoint = tokenEndpoint;
        this.tokenStore = tokenStore;
        this.userRepository = userRepository;
    }

    @GetMapping("/oauth/user")
    public ResponseEntity<?> getUser(Principal principal, @RequestParam
            Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
        ResponseEntity<OAuth2AccessToken> responseEntity = tokenEndpoint.postAccessToken(principal, parameters);
        if (responseEntity.getStatusCode().equals(HttpStatus.OK)) {
            OAuth2AccessToken token = responseEntity.getBody();
            OAuth2Authentication authentication = tokenStore.readAuthentication(token);
            if(authentication != null){
                Object detail = authentication.getPrincipal();
                if(detail instanceof CustomUserDetails){
                    return ResponseEntity.ok(userRepository.selectSelf((CustomUserDetails) detail));
                }
            }
        }
        return ResponseEntity.badRequest().build();
    }

}
