package org.jasig.cas.adaptors.ldappwd.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jasig.cas.adaptors.ldappwd.util.exceptions.AccountNotFoundException;
import org.jasig.cas.authentication.handler.AuthenticationException;

/**
 * Ldap Error Code Processor : Locked Account processor
 * 
 * @author Philippe MARASSE
 */
public final class AccountNotFoundErrorProcessor extends AbstractLdapErrorDetailProcessor {

    private final Pattern pattern = Pattern.compile(AccountNotFoundException.ACCOUNT_NOTFOUND_ERROR_REGEX);
    
    @Override
    boolean processErrorDetailInternal(String in_detail) throws AuthenticationException {
        logger.debug(" AccountNotFoundErrorProcessor - process:" + in_detail);
        final Matcher matcher = pattern.matcher(in_detail);
        if (matcher.find()) {
            if (logger.isDebugEnabled()) {
                logger.debug("Pattern matches : throwing AccountLockedException");
            }
            throw new AccountNotFoundException();
        }
        return false;
    }

    @Override
    String processTicketExceptionCodeInternal(String in_code) {
        System.out.println(" AccountNotFoundErrorProcessor - in_code:" + in_code);
        if (in_code.equals(AccountNotFoundException.ACCOUNT_NOTFOUND_CODE)) {
            return "showAccountNotFoundView";
            //return "error";
        }
        return null;
    }

}
