/*
 * Copyright 2007 The JA-SIG Collaborative. All rights reserved. See license
 * distributed with this file and available online at
 * http://www.ja-sig.org/products/cas/overview/license/
 */
package org.jasig.cas.adaptors.ldappwd;

//wti

import org.jasig.cas.adaptors.ldappwd.util.exceptions.AccountNotFoundException;

import org.jasig.cas.adaptors.ldappwd.util.AbstractLdapErrorDetailProcessor;
import org.jasig.cas.adaptors.ldappwd.util.NoOpErrorProcessor;
import org.jasig.cas.adaptors.ldap.AbstractLdapUsernamePasswordAuthenticationHandler;

import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.jasig.cas.util.LdapUtils;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.NameClassPairCallbackHandler;
import org.springframework.ldap.core.SearchExecutor;

import javax.naming.NameClassPair;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.ArrayList;
import java.util.List;

/**
 * Performs LDAP authentication via two distinct steps:
 *  <ol>
 *  <li>Search for an LDAP DN using arbitrary search filter.</li>
 *  <li>Bind using DN in first step with password provided by login Webflow.</li>
 *  </ol>
 *  <p>
 *  The search step is typically performed anonymously or using a constant
 *  authenticated context such as an administrator username/password or client
 *  certificate.  This step is suitable for LDAP connection pooling to improve
 *  efficiency and performance.
 * 
 * @author Scott Battaglia
 * @version $Revision: 24216 $ $Date: 2011-07-05 13:27:44 -0400 (Tue, 05 Jul 2011) $
 * @since 3.0.3
 */
public class BindLdapAuthenticationHandler extends
    AbstractLdapUsernamePasswordAuthenticationHandler {

    /** The default maximum number of results to return. */
    private static final int DEFAULT_MAX_NUMBER_OF_RESULTS = 1000;

    /** The default timeout. */
    private static final int DEFAULT_TIMEOUT = 1000;

    /** The search base to find the user under. */
    private String searchBase;

    /** The scope. */
    @Min(0)
    @Max(2)
    private int scope = SearchControls.SUBTREE_SCOPE;

    /** The maximum number of results to return. */
    private int maxNumberResults = DEFAULT_MAX_NUMBER_OF_RESULTS;

    /** The amount of time to wait. */
    private int timeout = DEFAULT_TIMEOUT;

    /** Boolean of whether multiple accounts are allowed. */
    private boolean allowMultipleAccounts;

    /**
     * Chaine de traitement pour les erreurs LDAP
     */
    @NotNull
    private AbstractLdapErrorDetailProcessor errorProcessor = new NoOpErrorProcessor();

    /** Log instance for logging events, info, warnings, errors, etc. */
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    protected final boolean authenticateUsernamePasswordInternal(
        final UsernamePasswordCredentials credentials)
        throws AuthenticationException {

        final List<String> cns = new ArrayList<String>();
        
        final SearchControls searchControls = getSearchControls();
        
        final String base = this.searchBase;
        final String transformedUsername = getPrincipalNameTransformer().transform(credentials.getUsername());
        final String filter = LdapUtils.getFilterWithValues(getFilter(), transformedUsername);
        this.getLdapTemplate().search(
            new SearchExecutor() {

                public NamingEnumeration executeSearch(final DirContext context) throws NamingException {
                    return context.search(base, filter, searchControls);
                }
            },
            new NameClassPairCallbackHandler(){

                public void handleNameClassPair(final NameClassPair nameClassPair) {
                    cns.add(nameClassPair.getNameInNamespace());
                }
            });
        
        
        if (cns.isEmpty()) {
            log.info("Search for " + filter + " returned 0 results.");
            //wti
            throw new AccountNotFoundException();
            //return false;
        }
        if (cns.size() > 1 && !this.allowMultipleAccounts) {
            log.warn("Search for " + filter + " returned multiple results, which is not allowed.");
            return false;
        }
        
        for (final String dn : cns) {
            DirContext test = null;
            String finalDn = composeCompleteDnToCheck(dn, credentials);
            try {
                this.log.debug("Performing LDAP bind with credential: " + dn);
                test = this.getContextSource().getContext(
                    finalDn,
                    credentials.getPassword());

                if (test != null) {
                    this.log.debug(" - auth ok - ");
                    processUserFromCoreapp();
                    return true;
                }
            } catch (final Exception e) {
				String details = e.getMessage();
                this.log.debug("LDAP server returned exception message: " + details);

                // Call Treatment chain
                errorProcessor.processErrorDetail(details);

                // if we catch an exception, just try the next cn
            } finally {
                LdapUtils.closeContext(test);
            }
        }

        return false;
    }
    
    protected void processUserFromCoreapp()
    {
        
    }

    protected String composeCompleteDnToCheck(final String dn,
        final UsernamePasswordCredentials credentials) {
        return dn;
    }

    private SearchControls getSearchControls() {
        final SearchControls constraints = new SearchControls();
        constraints.setSearchScope(this.scope);
        constraints.setReturningAttributes(new String[0]);
        constraints.setTimeLimit(this.timeout);
        constraints.setCountLimit(this.maxNumberResults);

        return constraints;
    }

    /**
     * Method to return whether multiple accounts are allowed.
     * @return true if multiple accounts are allowed, false otherwise.
     */
    protected boolean isAllowMultipleAccounts() {
        return this.allowMultipleAccounts;
    }

    /**
     * Method to return the max number of results allowed.
     * @return the maximum number of results.
     */
    protected int getMaxNumberResults() {
        return this.maxNumberResults;
    }

    /**
     * Method to return the scope.
     * @return the scope
     */
    protected int getScope() {
        return this.scope;
    }

    /**
     * Method to return the search base.
     * @return the search base.
     */
    protected String getSearchBase() {
        return this.searchBase;
    }

    /**
     * Method to return the timeout. 
     * @return the timeout.
     */
    protected int getTimeout() {
        return this.timeout;
    }

    public final void setScope(final int scope) {
        this.scope = scope;
    }

    /**
     * @param allowMultipleAccounts The allowMultipleAccounts to set.
     */
    public void setAllowMultipleAccounts(final boolean allowMultipleAccounts) {
        this.allowMultipleAccounts = allowMultipleAccounts;
    }

    /**
     * @param maxNumberResults The maxNumberResults to set.
     */
    public final void setMaxNumberResults(final int maxNumberResults) {
        this.maxNumberResults = maxNumberResults;
    }

    /**
     * @param searchBase The searchBase to set.
     */
    public final void setSearchBase(final String searchBase) {
        this.searchBase = searchBase;
    }

    /**
     * @param timeout The timeout to set.
     */
    public final void setTimeout(final int timeout) {
        this.timeout = timeout;
    }

    /**
     * Sets the context source for LDAP searches.  This method may be used to
     * support use cases like the following:
     * <ul>
     * <li>Pooling of LDAP connections used for searching (e.g. via instance
     * of {@link PoolingContextSource}).</li>
     * <li>Searching with client certificate credentials.</li>
     * </ul>
     * <p>
     * If this is not defined, the context source defined by
     * {@link #setContextSource(ContextSource)} is used.
     *
     * @param contextSource LDAP context source.
     */
    public final void setSearchContextSource(final ContextSource contextSource) {
        setLdapTemplate(new LdapTemplate(contextSource));
    }

    /**
     * @param errorProcessor Processor chain for ldap error details
     */
    public final void setErrorProcessor(final AbstractLdapErrorDetailProcessor errorProcessor) {
        this.errorProcessor = errorProcessor;
    }
}
