package org.springframework.security.authentication;

/**
 * @author qingsheng.chen@hand-china.com
 */
public class ClientAuthenticationToken extends AbstractAuthenticationToken {
    private final Object principal;

    /**
     * 客户端 Token 授权
     *
     * @param principal 客户端对象
     */
    public ClientAuthenticationToken(Object principal) {
        super(null);
        this.principal = principal;
        this.setAuthenticated(principal != null);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
