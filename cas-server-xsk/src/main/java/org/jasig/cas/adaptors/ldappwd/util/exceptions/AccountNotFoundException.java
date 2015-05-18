/**
 *    WTI : 
 * exception for check if account found on AD
 */
package org.jasig.cas.adaptors.ldappwd.util.exceptions;

import org.jasig.cas.authentication.handler.AuthenticationException;

public final class AccountNotFoundException extends AuthenticationException {

    private static final long serialVersionUID = -5838108564896634659L;

    /**
     * Spring uses this code to map the locale specific error message from properties files in WEB-INF/classes/.
     */
    public static final String ACCOUNT_NOTFOUND_CODE = "error.authentication.account.ad_notfound";

    /**
     * Regex to match Active Directory (and other LDAP directories) error code for an account being locked
     */
    public static final String ACCOUNT_NOTFOUND_ERROR_REGEX = "\\D533\\D|\\D701\\D|\\D53\\D|Account inactivated|OperationNotSupportedException";

    public AccountNotFoundException() {
        super(AccountNotFoundException.ACCOUNT_NOTFOUND_CODE);
    }

    public AccountNotFoundException(final String code) {
        super(code);
    }
}
