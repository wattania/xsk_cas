/*
 * Copyright 2007 The JA-SIG Collaborative. All rights reserved. See license
 * distributed with this file and available online at
 * http://www.uportal.org/license.html
 */
package org.jasig.cas.adaptors.x509.authentication.handler.support;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRLEntry;
import java.util.Date;


/**
 * Exception that describes a revoked X.509 certificate.
 *
 * @author Marvin S. Addison
 * @version $Revision: 22985 $
 * @since 3.4.6
 *
 */
public class RevokedCertificateException extends GeneralSecurityException {
   
    /** Serialization marker */
    private static final long serialVersionUID = 8827788431199129708L;

    /** OID for reasonCode CRL extension */
    public static final String CRL_REASON_OID = "2.5.29.21";
    
    /** CRL revocation reason codes per RFC 3280 */ 
    public enum Reason {
        Unspecified,
        KeyCompromise,
        CACompromise,
        AffiliationChanged,
        Superseded,
        CessationOfOperation,
        CertificateHold,
        RemoveFromCRL,
        PrivilegeWithdrawn,
        AACompromise;
        
        public static Reason fromCode(final int code) {
            for (int i = 0; i < Reason.values().length; i++) {
                if (i == code) {
                    return Reason.values()[i];
                }
            }
            throw new IllegalArgumentException("Unknown CRL reason code.");
        }
    }
    
    private Date revocationDate;
    
    private BigInteger serial;
    
    private Reason reason;
    
    public RevokedCertificateException(final Date revoked, final BigInteger serial) {
        this(revoked, serial, null);
    }

    public RevokedCertificateException(final Date revoked, final BigInteger serial, final Reason reason) {
        this.revocationDate = revoked;
        this.serial = serial;
        this.reason = reason;
    }

    public RevokedCertificateException(final X509CRLEntry entry) {
        this.revocationDate = entry.getRevocationDate();
        this.serial = entry.getSerialNumber();
        if (entry.hasExtensions()) {
            try {
                final int code = Integer.parseInt(
                    new String(entry.getExtensionValue(CRL_REASON_OID), "ASCII"));
                if (code < Reason.values().length) {
                    this.reason = Reason.fromCode(code);
                }
            } catch (final Exception e) {
                // Ignore invalid reason codes
            }
        }
    }
    
    /**
     * @return Returns the revocationDate.
     */
    public Date getRevocationDate() {
        return this.revocationDate;
    }

    /**
     * @return Returns the serial.
     */
    public BigInteger getSerial() {
        return this.serial;
    }
    
    /**
     * @return Returns the reason.
     */
    public Reason getReason() {
        return this.reason;
    }
    
    /** {@inheritDoc} */
    @Override
    public String getMessage() {
        if (this.reason != null) {
	        return String.format("Certificate %s revoked on %s for reason %s",
	            this.serial, this.revocationDate, this.reason);
        }
        return String.format("Certificate %s revoked on %s", this.serial, this.revocationDate);
    }
}
