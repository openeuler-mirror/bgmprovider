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

package org.openeuler.gm;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * SSLSocket Test
 */
public class SSLSocketTest extends SSLSocketTestBase {

    @BeforeClass
    public static void beforeClass() {
        System.setProperty("jdk.tls.client.protocols", "TLSv1.3,TLSv1.2,GMTLS");
        insertProviders();
    }

    @Test
    public void testGMTLSContextECDHE() {
        test("GMTLS", null, null,
                "GMTLS", new String[]{"GMTLS"}, new String[]{"ECDHE_SM4_CBC_SM3"}, true);
        test("GMTLS", null, null,
                "GMTLS", new String[]{"GMTLS"}, new String[]{"ECDHE_SM4_GCM_SM3"}, true);
    }

    @Test
    public void testGMTLSContextECC() {
        test("GMTLS", null, null,
                "GMTLS", new String[]{"GMTLS"}, new String[]{"ECC_SM4_CBC_SM3"});
        test("GMTLS", null, null,
                "GMTLS", new String[]{"GMTLS"}, new String[]{"ECC_SM4_GCM_SM3"});
    }

    @Test
    public void testGMTLSAdaptive() {
        test("GMTLS", null, null,
                "TLSv1.2", new String[]{"TLSv1.2"}, new String[]{"TLS_RSA_WITH_AES_256_CBC_SHA256"},
                "TLSv1.2", "TLS_RSA_WITH_AES_256_CBC_SHA256");
        //TLS_DHE_RSA_WITH_AES_256_CBC_SHA process ServerKeyExchange Message
        test("GMTLS", null, null,
                "TLSv1.2", new String[]{"TLSv1.2"}, new String[]{"TLS_DHE_RSA_WITH_AES_256_CBC_SHA"},
                "TLSv1.2", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
    }

    @Test
    public void testGMTLSProtocolPriority() {
        test("GMTLS", null, null,
                "TLS", null, new String[]{"TLS_RSA_WITH_AES_256_CBC_SHA256",
                        "ECC_SM4_CBC_SM3"},
                "GMTLS", "ECC_SM4_CBC_SM3");
    }

    @Test
    public void testGMTLSCiphersuitePriority() {
        // ECC_SM4_CBC_SM3 > ECDHE_SM4_CBC_SM3 > ECC_SM4_GCM_SM3 > ECDHE_SM4_GCM_SM3
        test("GMTLS", null, null,
                "TLS", null, null,
                "GMTLS", "ECC_SM4_CBC_SM3");
    }

    @Test
    public void testTLSContext() {
        test("TLS", null, null,
                "TLS", new String[]{"GMTLS"}, new String[]{"ECC_SM4_CBC_SM3"});
        test("TLS", null, null,
                "TLS", new String[]{"GMTLS"}, new String[]{"ECC_SM4_GCM_SM3"});

        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.2"}, new String[]{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"});

        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.3"}, null);

        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.3"}, new String[]{"TLS_AES_128_GCM_SHA256"});
    }

    @Test
    public void testTLSGMCipherSuite() {
        System.setProperty("bgmprovider.t12gmciphersuite", "true");
        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.2"}, new String[]
                {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECC_SM4_CBC_SM3"},
                "TLSv1.2", "ECC_SM4_CBC_SM3");
        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.2"}, new String[]
                        {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE_SM4_CBC_SM3"},
                true, "TLSv1.2", "ECDHE_SM4_CBC_SM3");
        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.3"}, new String[]
                        {"TLS_AES_128_GCM_SHA256", "ECC_SM4_CBC_SM3"},
                "TLSv1.3", "TLS_AES_128_GCM_SHA256");
        System.setProperty("bgmprovider.t12gmciphersuite", "false");
    }

    @Test
    public void testServerRenegotiate() {
        test("TLS", null, null,
                "TLS", new String[]{"GMTLS"}, new String[]{"ECC_SM4_CBC_SM3"},
                Status.SERVER_RENEGOTIATE);
    }

    @Test
    public void testClientRenegotiate() {
        test("TLS", null, null,
                "TLS", new String[]{"GMTLS"}, new String[]{"ECC_SM4_CBC_SM3"},
                Status.CLIENT_RENEGOTIATE);
    }

    @Test
    public void testTLS12ServerRenegotiate() {
        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.2"}, new String[]{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
                Status.SERVER_RENEGOTIATE);
    }

    @Test
    public void testTLS12ClientRenegotiate() {
        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.2"}, new String[]{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
                Status.CLIENT_RENEGOTIATE);
    }

    @Test
    public void testTLS12SessionResumption() {
        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.2"}, new String[]{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
                Status.SESSION_RESUMPTION_START);
        System.setProperty("bgmprovider.t12gmciphersuite", "true");
        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.2"}, new String[]
                {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECC_SM4_CBC_SM3"},
                Status.SESSION_RESUMPTION_START);
        System.setProperty("bgmprovider.t12gmciphersuite", "false");
    }

    @Test
    public void testGMTLSSessionResumption() {
        test("TLS", null, null,
                "TLS", new String[]{"GMTLS"}, new String[]{"ECC_SM4_CBC_SM3"},
                Status.SESSION_RESUMPTION_START);
    }

    @Test
    public void testPKIX() {
        test("TLS", null, null,
                "TLS", new String[]{"GMTLS"}, new String[]{"ECC_SM4_CBC_SM3"}, "PKIX");
        test("TLS", null, null,
                "TLS", new String[]{"GMTLS"}, new String[]{"ECC_SM4_GCM_SM3"}, "PKIX");

        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.2"}, new String[]{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"}, "PKIX");

        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.3"}, null, "PKIX");

        test("TLS", null, null,
                "TLS", new String[]{"TLSv1.3"}, new String[]{"TLS_AES_128_GCM_SHA256"}, "PKIX");
    }

    /**
     * By default, the server does not enable TLSv1.2 protocol support for GM cipher suites.
     * The server should skip the GM cipher suites when selecting the cipher suite.
     * When testing, put the GM cipher suites in the front.
     */
    @Test
    public void testTLS12SkipGMCipher() {
        // Test TLSv1.2 protocol support for GM cipher suites is not enabled.
        test("TLS", new String[]{"GMTLS", "TLSv1.3", "TLSv1.2"},
                new String[]{"ECC_SM4_CBC_SM3", "TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
                "TLS", new String[]{"TLSv1.2"},
                new String[]{"ECC_SM4_CBC_SM3", "TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
                "TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");

        // Test TLSv1.2 protocol support for GM cipher suites is enabled.
        try {
            System.setProperty("bgmprovider.t12gmciphersuite", "true");
            test("TLS", new String[]{"GMTLS", "TLSv1.3", "TLSv1.2"},
                    new String[]{"ECC_SM4_CBC_SM3", "TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
                    "TLS", new String[]{"TLSv1.2"},
                    new String[]{"ECC_SM4_CBC_SM3", "TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
                    "TLSv1.2", "ECC_SM4_CBC_SM3");
        } finally {
            System.setProperty("bgmprovider.t12gmciphersuite", "false");
        }
    }
}
