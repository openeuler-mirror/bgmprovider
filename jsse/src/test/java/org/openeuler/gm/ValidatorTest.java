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
import org.junit.Test;
import org.openeuler.sun.security.validator.Validator;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;

import static org.openeuler.gm.TestUtils.getPath;

public class ValidatorTest extends BaseTest {
    private static final String PATH = getPath("server.truststore");
    private static final char[] PASSWORD = "12345678".toCharArray();
    private static final KeyStore trustStore = getTrustStore();

    @Test
    public void test() throws Exception {
        Validator validator = Validator.getInstance(Validator.TYPE_PKIX, Validator.VAR_TLS_SERVER, getParams());
        X509Certificate[] certs = getChain();
        X509Certificate[] validatedCerts = validator.validate(certs);
        Assert.assertArrayEquals(certs, validatedCerts);
    }

    private static PKIXBuilderParameters getParams() throws Exception {
        PKIXBuilderParameters pbp =
                new PKIXBuilderParameters(getTmpTrustStore(),
                        new X509CertSelector());
        pbp.setRevocationEnabled(false);
        return pbp;
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

    private static X509Certificate[] getChain() throws KeyStoreException {
        X509Certificate[] x509CertificateChain = new X509Certificate[2];
        x509CertificateChain[0] = (X509Certificate) trustStore.getCertificate("server-sm2-sig");
        x509CertificateChain[1] = (X509Certificate) trustStore.getCertificate("server-rootca");
        return x509CertificateChain;
    }

    private static KeyStore getTmpTrustStore() throws Exception {
        KeyStore tmpTrustStore = KeyStore.getInstance("PKCS12");
        tmpTrustStore.load(null, null);
        tmpTrustStore.setCertificateEntry("server-rootca", trustStore.getCertificate("server-rootca"));
        return tmpTrustStore;
    }
}
