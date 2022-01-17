/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.tomcat;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.junit.Test;

public class KeyStoreFileTest extends TomcatBaseTest {
    private static final Log log = LogFactory.getLog(KeyStoreFileTest.class);

    @Test
    public void testSM2() throws Throwable {
        Cert[] certs = new Cert[]{Cert.KEYSTORE_SM2};
        TestParameters serverParameters = new TestParameters.Builder()
                .protocols(new String[]{"GMTLS"})
                .ciphers(new String[]{"ECC_SM4_CBC_SM3"})
                .certs(certs)
                .builder();
        TestParameters clientParameters = new TestParameters.Builder()
                .protocols(new String[]{"GMTLS"})
                .expectedCipher("ECC_SM4_CBC_SM3")
                .builder();
        testConnect(serverParameters, clientParameters);
    }

    @Test
    public void testSM2AndEC() throws Throwable {
        Cert[] certs = new Cert[]{Cert.KEYSTORE_SM2_EC};
        TestParameters serverParameters = new TestParameters.Builder()
                .protocols(new String[]{"GMTLS", "TLSv1.3", "TLSv1.2"})
                .ciphers(new String[]{"TLS_AES_128_GCM_SHA256",
                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECC_SM4_CBC_SM3"})
                .certs(certs)
                .builder();

        // GMTLS
        TestParameters clientParameters = new TestParameters.Builder()
                .protocols(new String[]{"GMTLS"})
                .expectedCipher("ECC_SM4_CBC_SM3")
                .builder();
        testConnect(serverParameters, clientParameters);

        // TLSv1.2
        TestParameters.Builder builder = new TestParameters.Builder()
                .protocols(new String[]{"TLSv1.2"})
                .expectedCipher("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");

        if (TestUtils.getTomcatVersion().equals(TomcatVersion.V9_0_0_M3)) {
            log.warn("The order of supported cipher suites configured in tomcat " +
                    TestUtils.getTomcatVersion() + " is out of order");
            builder.ciphers(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
        }
        clientParameters = builder.builder();
        testConnect(serverParameters, clientParameters);

        // TLSv1.3
        if (TestUtils.isSupportTLS13()) {
            clientParameters = new TestParameters.Builder()
                    .protocols(new String[]{"TLSv1.3"})
                    .expectedCipher("TLS_AES_128_GCM_SHA256")
                    .builder();
            testConnect(serverParameters, clientParameters);
        } else {
            log.warn("Tomcat" + TestUtils.getTomcatVersion() + "version does not support TLSv1.3");
        }
    }

    @Test
    public void testSM2AndRSA() throws Throwable {
        Cert[] certs = new Cert[]{Cert.KEYSTORE_SM2_RSA};
        TestParameters serverParameters = new TestParameters.Builder()
                .protocols(new String[]{"GMTLS", "TLSv1.3", "TLSv1.2"})
                .ciphers(new String[]{"TLS_AES_128_GCM_SHA256",
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECC_SM4_CBC_SM3"})
                .certs(certs)
                .builder();

        // GMTLS
        TestParameters clientParameters = new TestParameters.Builder()
                .protocols(new String[]{"GMTLS"})
                .expectedCipher("ECC_SM4_CBC_SM3")
                .builder();
        testConnect(serverParameters, clientParameters);

        // TLSv1.2
        TestParameters.Builder builder = new TestParameters.Builder()
                .protocols(new String[]{"TLSv1.2"})
                .expectedCipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        if (TestUtils.getTomcatVersion().equals(TomcatVersion.V9_0_0_M3)) {
            builder.ciphers(new String[]{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"});
        }
        clientParameters = builder.builder();
        testConnect(serverParameters, clientParameters);

        // TLSv1.3
        if (TestUtils.isSupportTLS13()) {
            clientParameters = new TestParameters.Builder()
                    .protocols(new String[]{"TLSv1.3"})
                    .expectedCipher("TLS_AES_128_GCM_SHA256")
                    .builder();
            testConnect(serverParameters, clientParameters);
        } else {
            log.warn("Tomcat" + TestUtils.getTomcatVersion() + "version does not support TLSv1.3");
        }
    }

    @Test
    public void testCertAttributesWithExtraSpaces() throws Throwable {
        Cert[] certs = new Cert[]{Cert.KEYSTORE_WITH_EXTRA_SPACES};
        TestParameters serverParameters = new TestParameters.Builder()
                .protocols(new String[]{"GMTLS", "TLSv1.3", "TLSv1.2"})
                .ciphers(new String[]{"TLS_AES_128_GCM_SHA256",
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECC_SM4_CBC_SM3"})
                .certs(certs)
                .builder();

        // GMTLS
        TestParameters clientParameters = new TestParameters.Builder()
                .protocols(new String[]{"GMTLS"})
                .expectedCipher("ECC_SM4_CBC_SM3")
                .builder();
        testConnect(serverParameters, clientParameters);

        // TLSv1.2
        TestParameters.Builder builder = new TestParameters.Builder()
                .protocols(new String[]{"TLSv1.2"})
                .expectedCipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        if (TestUtils.getTomcatVersion().equals(TomcatVersion.V9_0_0_M3)) {
            builder.ciphers(new String[]{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"});
        }
        clientParameters = builder.builder();
        testConnect(serverParameters, clientParameters);

        // TLSv1.3
        if (TestUtils.isSupportTLS13()) {
            clientParameters = new TestParameters.Builder()
                    .protocols(new String[]{"TLSv1.3"})
                    .expectedCipher("TLS_AES_128_GCM_SHA256")
                    .builder();
            testConnect(serverParameters, clientParameters);
        } else {
            log.warn("Tomcat" + TestUtils.getTomcatVersion() + "version does not support TLSv1.3");
        }
    }

    @Test
    public void testSM2Uppercase() throws Throwable {
        Cert[] certs = new Cert[]{Cert.KEYSTORE_SM2_UPPERCASE_KEY_ALIAS};
        TestParameters serverParameters = new TestParameters.Builder()
                .protocols(new String[]{"GMTLS"})
                .ciphers(new String[]{"ECC_SM4_CBC_SM3"})
                .certs(certs)
                .builder();
        TestParameters clientParameters = new TestParameters.Builder()
                .protocols(new String[]{"GMTLS"})
                .expectedCipher("ECC_SM4_CBC_SM3")
                .builder();
        testConnect(serverParameters, clientParameters);
    }
}
