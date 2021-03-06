/*
 * Copyright 2007 The JA-SIG Collaborative. All rights reserved. See license
 * distributed with this file and available online at
 * http://www.uportal.org/license.html
 */
package org.jasig.cas.adaptors.x509.authentication.handler.support;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import edu.vt.middleware.crypt.util.CryptReader;


/**
 * Base class for {@link RevocationChecker} unit tests.
 *
 * @author Marvin S. Addison
 * @version $Revision: 22985 $
 * @since 3.4.6
 *
 */
public abstract class AbstractCRLRevocationCheckerTests {
    
    /** Certificate to be tested */
    private X509Certificate[] certificates;

    /** Expected result of check; null for success */
    private GeneralSecurityException expected;
    

    /**
     * Creates a new test instance with given parameters.
     *
     * @param certFiles File names of certificates to check.
     * @param expected Expected result of check; null to indicate expected success.
     */
    public AbstractCRLRevocationCheckerTests(
        final String[] certFiles,
        final GeneralSecurityException expected) {

        this.expected = expected;
        this.certificates = new X509Certificate[certFiles.length];
        int i = 0;
        for (String file : certFiles) {
            this.certificates[i++] = readCertificate(file);
        }

    }

    /**
     * Test method for {@link AbstractCRLRevocationChecker#check(X509Certificate)}.
     */
    @Test
    public void testCheck() {
        try {
            for (X509Certificate cert : this.certificates) {
                getChecker().check(cert);
            }
            if (this.expected != null) {
                Assert.fail("Expected exception of type " + this.expected.getClass());
            }
        } catch (GeneralSecurityException e) {
            if (this.expected == null) {
                e.printStackTrace();
                Assert.fail("Revocation check failed unexpectedly with exception: " + e);
            } else {
                final Class<?> expectedClass = this.expected.getClass();
                final Class<?> actualClass = e.getClass();
                Assert.assertTrue(
                    String.format("Expected exception of type %s but got %s", expectedClass, actualClass),
                    expectedClass.isAssignableFrom(actualClass));
            }
        }
    }
    
    protected abstract RevocationChecker getChecker();

    private X509Certificate readCertificate(final String file) {
        InputStream in = null;
        try {
            in = new ClassPathResource(file).getInputStream();
            return (X509Certificate) CryptReader.readCertificate(in);
        } catch (Exception e) {
            throw new RuntimeException("Error reading certificate " + file, e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
    }
}
