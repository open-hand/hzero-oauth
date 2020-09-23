package org.hzero.oauth.security.exception;

/**
 * @author bojiangzhou
 */
public enum LoginExceptions {

    USERNAME_NOT_FOUND("hoth.warn.usernameNotFound"),

    PHONE_NOT_FOUND("hoth.warn.phoneNotFound"),

    USER_NOT_ACTIVATED("hoth.warn.userNotActive"),

    ACCOUNT_LOCKED("hoth.warn.accountLocked"),

    ACCOUNT_EXPIRE("hoth.warn.accountExpire"),

    TENANT_INVALID("hoth.warn.tenantInvalid"),

    TENANT_DISABLED("hoth.warn.tenantDisabled"),

    PASSWORD_ERROR("hoth.warn.passwordError"),

    USERNAME_OR_PASSWORD_ERROR("hoth.warn.usernameNotFoundOrPasswordIsWrong"),

    LOGIN_ERROR_MORE_THEN_MAX_TIME("hoth.warn.loginErrorMaxTimes"),

    LDAP_IS_DISABLE("hoth.warn.ldapIsDisable"),

    CAPTCHA_NULL("hoth.warn.captchaNull"),

    CAPTCHA_ERROR("hoth.warn.captchaWrong"),

    PHONE_NOT_CHECK("hoth.warn.phoneNotCheck"),

    EMAIL_NOT_CHECK("hoth.warn.emailNotCheck"),

    PHONE_AND_EMAIL_NOT_CHECK("hoth.warn.phoneAndEmailNotCheck"),

    DEFAULT_TENANT_ROLE_NONE("hoth.warn.defaultTenantRoleNull"),

    LOGIN_MOBILE_CAPTCHA_NULL("hoth.warn.loginMobileCaptchaNull"),

    ROLE_NONE("hoth.warn.roleNone"),

    DECODE_PASSWORD_ERROR("hoth.warn.decodePasswordError"),

    PASSWORD_EXPIRED("hoth.warn.passwordExpired"),

    PASSWORD_FORCE_MODIFY("hoth.warn.passwordForceModify"),

    USER_NOT_ACCESS_CLIENT("hoth.warn.userNotAccessClient"),

    CLIENT_NOT_FOUND("hoth.warn.clientNotFound"),

    DUPLICATE_PASSWORD("hoth.warn.duplicatePassword")

    ;

    private final String value;

    LoginExceptions(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
