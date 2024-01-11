/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd. All rights reserved.
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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import static org.openeuler.gm.TestUtils.getPath;

public class RFC8998Test extends SSLSocketTestBase {
    private static final String KEYSTORE_TYPE = "PKCS12";

    private static final char[] DEFAULT_PASSWORD = "12345678".toCharArray();

    // server keystore path
    private static final String SERVER_KEYSTORE_PATH = getPath("server-sm2-sig.keystore");

    // server truststore path
    private static final String SERVER_TRUSTSTORE_PATH = getPath("client-sm2-sig.truststore");

    // client keystore path
    private static final String CLIENT_KEYSTORE_PATH = getPath("client-sm2-sig.keystore");

    // client truststore path
    private static final String CLIENT_TRUSTSTORE_PATH = getPath("server-sm2-sig.truststore");

    @BeforeClass
    public static void beforeClass() {
        System.setProperty("bgmprovider.tls.enableRFC8998", "true");
        System.setProperty("jdk.tls.namedGroups", "curvesm2");
        System.setProperty("jdk.tls.client.SignatureSchemes", "sm2sig_sm3");
        insertProviders();
    }

    @Test
    public void testTLS_SM4_GCM_SM3() {
        ReqParameters serverReqParameters = new ReqParameters.Builder()
                .build();
        ReqParameters clientReqParameters = new ReqParameters.Builder()
                .enableProtocols(new String[]{"TLSv1.3"})
                .enableCipherSuites(new String[]{"TLS_SM4_GCM_SM3"})
                .build();
        test(serverReqParameters, clientReqParameters);
    }

    @Test
    public void testTLS_SM4_CCM_SM3() {
        ReqParameters serverReqParameters = new ReqParameters.Builder()
                .build();
        ReqParameters clientReqParameters = new ReqParameters.Builder()
                .enableProtocols(new String[]{"TLSv1.3"})
                .enableCipherSuites(new String[]{"TLS_SM4_CCM_SM3"})
                .build();
        test(serverReqParameters, clientReqParameters);
    }

    @Test
    public void testTLS_SM4_GCM_SM3withSM2Cert() {
        testRFC8998CipherSuitesWithSM2Cert(new String[]{"TLSv1.3"}, new String[]{"TLS_SM4_GCM_SM3"});
    }

    @Test
    public void testTLS_SM4_CCM_SM3withSM2Cert() {
        testRFC8998CipherSuitesWithSM2Cert(new String[]{"TLSv1.3"}, new String[]{"TLS_SM4_CCM_SM3"});
    }

    @Test
    public void testServerRenegotiate() {
        testRFC8998CipherSuitesWithSM2Cert(new String[]{"TLSv1.3"}, new String[]{"TLS_SM4_GCM_SM3"},
                Status.SERVER_RENEGOTIATE);
    }

    @Test
    public void testClientRenegotiate() {
        testRFC8998CipherSuitesWithSM2Cert(new String[]{"TLSv1.3"}, new String[]{"TLS_SM4_GCM_SM3"},
               Status.CLIENT_RENEGOTIATE);
    }

    @Test
    public void testSessionResumption() {
        testRFC8998CipherSuitesWithSM2Cert(new String[]{"TLSv1.3"}, new String[]{"TLS_SM4_GCM_SM3"},
                Status.SESSION_RESUMPTION_START);
    }

    private void testRFC8998CipherSuitesWithSM2Cert(String[] enableProtocols, String[] enableCipherSuites) {
        testRFC8998CipherSuitesWithSM2Cert(enableProtocols, enableCipherSuites, null);
    }

    private void testRFC8998CipherSuitesWithSM2Cert(String[] enableProtocols, String[] enableCipherSuites,
                                                    Status status) {
        // server ReqParameters
        KeyStoreParameters serverKeyStoreParameters = new KeyStoreParameters(
                KEYSTORE_TYPE, SERVER_KEYSTORE_PATH, DEFAULT_PASSWORD, KeyManagerFactory.getDefaultAlgorithm());
        KeyStoreParameters serverTrustStoreParameters = new KeyStoreParameters(
                KEYSTORE_TYPE, SERVER_TRUSTSTORE_PATH, DEFAULT_PASSWORD, TrustManagerFactory.getDefaultAlgorithm());
        ReqParameters.Builder serverBuilder = new ReqParameters.Builder()
                .keyStoreParameters(serverKeyStoreParameters)
                .trustStoreParameters(serverTrustStoreParameters);
        if (status != null) {
            serverBuilder.status(status);
        }
        ReqParameters serverReqParameters = serverBuilder.build();

        // client ReqParameters
        KeyStoreParameters clientKeyStoreParameters = new KeyStoreParameters(
                KEYSTORE_TYPE, CLIENT_KEYSTORE_PATH, DEFAULT_PASSWORD, KeyManagerFactory.getDefaultAlgorithm());
        KeyStoreParameters clientTrustStoreParameters = new KeyStoreParameters(
                KEYSTORE_TYPE, CLIENT_TRUSTSTORE_PATH, DEFAULT_PASSWORD, TrustManagerFactory.getDefaultAlgorithm());
        ReqParameters.Builder clientBuilder=new ReqParameters.Builder()
                .keyStoreParameters(clientKeyStoreParameters)
                .trustStoreParameters(clientTrustStoreParameters)
                .enableProtocols(enableProtocols)
                .enableCipherSuites(enableCipherSuites);
        if (status != null) {
            clientBuilder.status(status);
        }
        ReqParameters clientReqParameters = clientBuilder.build();

        // test
        test(serverReqParameters, clientReqParameters);
    }
}
