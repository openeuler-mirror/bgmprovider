/*
 * Copyright (c) 2022, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Huawei designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Huawei in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please visit https://gitee.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */

package org.openeuler.gm;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import sun.security.x509.X509CertImpl;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.openeuler.gm.TestUtils.getPath;

public class X509CertImplHandlerTest extends BaseTest {
    private static final String PATH = getPath("server.truststore");
    private static final char[] PASSWORD = "12345678".toCharArray();
    private static final String EXPECTED_FINGERPRINT =
            "4DE5D694EC2C635DD0ED57F6D852A2092F8727CFA0B58962853189FACDDC37EA";
    private static KeyStore trustStore;


    @BeforeClass
    public static void beforeClass() {
        trustStore = getTrustStore();
    }

    @Test
    public void testNonStaticGetFingerprintMethod() throws KeyStoreException, CertificateException {
        Certificate certificate = trustStore.getCertificate("server-sm2-sig");
        X509CertImpl x509Cert = new X509CertImpl(certificate.getEncoded());
        String fingerprint = X509CertImplHandler.getFingerprint("SM3", x509Cert);
        Assert.assertEquals(EXPECTED_FINGERPRINT, fingerprint);
    }

    @Test
    public void testStaticGetFingerprintMethod() throws KeyStoreException {
        Certificate certificate = trustStore.getCertificate("server-sm2-sig");
        String fingerprint = X509CertImplHandler.getFingerprint("SM3", (X509Certificate) certificate);
        Assert.assertEquals(EXPECTED_FINGERPRINT, fingerprint);
    }

    private static KeyStore getTrustStore() {
        KeyStore keyStore;
        try (FileInputStream fileInputStream = new FileInputStream(PATH)) {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fileInputStream, PASSWORD);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return keyStore;
    }
}
