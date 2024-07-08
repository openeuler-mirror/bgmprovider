/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.org.eclipse.jetty;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import org.junit.Assert;
import org.junit.Test;
import org.openeuler.commons.BaseTest;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;

import static org.openeuler.commons.TestConstants.*;

public class JettyTest extends BaseTest {

    private static int serverPort = 0;
    private static final String path = "/test";
    private static final String host = "localhost";
    private static final String scheme = "https";
    private static final String[] TEST_GM_CIPHER_SUITES = {
            ECC_SM4_CBC_SM3,
            ECC_SM4_GCM_SM3,
            ECDHE_SM4_CBC_SM3,
            ECDHE_SM4_GCM_SM3
    };

    private static final String[] TEST_GM_ECC_CIPHER_SUITES = {
            ECC_SM4_CBC_SM3,
            ECC_SM4_GCM_SM3
    };

    @Test
    public void testTLS() throws Exception {
        Server server = null;
        try {
            server = startServer(true);
            startClient(TLS13_PROTOCOL, TLS_AES_128_GCM_SHA256);
        } finally {
            if (server != null) {
                server.stop();
            }
        }
    }

    @Test
    public void testGMTLSWithClientAuth() throws Exception {
        Server server = null;
        try {
            server = startServer(true);
            for (String cipherSuite : TEST_GM_CIPHER_SUITES) {
                startClient(GMTLS_PROTOCOL, cipherSuite);
            }
        } finally {
            if (server != null) {
                server.stop();
            }
        }
    }

    @Test
    public void testGMTLSWithNoClientAuth() throws Exception {
        Server server = null;
        try {
            server = startServer(false);
            for (String cipherSuite : TEST_GM_ECC_CIPHER_SUITES) {
                startClient(GMTLS_PROTOCOL, cipherSuite);
            }
        } finally {
            if (server != null) {
                server.stop();
            }
        }
    }

    private static Server startServer(boolean needClientAuth) throws Exception {
        // HttpConfiguration
        HttpConfiguration httpsConfig = new HttpConfiguration();
        httpsConfig.addCustomizer(new SecureRequestCustomizer());

        // SslContextFactory
        SslContextFactory sslContextFactory = createServerSslContextFactory(needClientAuth);

        // SslConnectionFactory
        HttpConnectionFactory h1 = new HttpConnectionFactory(httpsConfig);
        SslConnectionFactory sslConnectionFactory = new SslConnectionFactory(sslContextFactory, "http/1.1");

        // connector
        Server server = new Server();
        ServerConnector connector = new ServerConnector(server, sslConnectionFactory, h1);
        server.addConnector(connector);
        server.setHandler(new AbstractHandler() {
            @Override
            public void handle(String target, Request baseRequest,
                               HttpServletRequest request, HttpServletResponse response)
                    throws IOException, ServletException {
                if (response.isCommitted() || baseRequest.isHandled()) {
                    return;
                }
                baseRequest.setHandled(true);
                if (path.equals(target)) {
                    response.setStatus(HttpServletResponse.SC_OK);
                } else {
                    response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                }
            }
        });
        server.start();
        serverPort = connector.getLocalPort();
        return server;
    }

    private static SslContextFactory createServerSslContextFactory(boolean needClientAuth) {
        SslContextFactory.Server sslSocketFactory = new SslContextFactory.Server();
        sslSocketFactory.setProtocol(GMTLS_PROTOCOL);
        sslSocketFactory.setKeyStorePath(SERVER_KEYSTORE_PATH);
        sslSocketFactory.setKeyStorePassword(SERVER_KEYSTORE_PASSWORD);
        sslSocketFactory.setTrustStorePath(CLIENT_TRUSTSTORE_PATH);
        sslSocketFactory.setTrustStorePassword(CLIENT_TRUSTSTORE_PASSWORD);
        sslSocketFactory.setNeedClientAuth(needClientAuth);
        return sslSocketFactory;
    }

    private static void startClient(String protocol, String cipherSuite) throws Exception {
        // SslContextFactory
        SslContextFactory sslContextFactory = createClientSslContextFactory(protocol, cipherSuite);
        // HttpClient
        HttpClient httpClient = null;
        try {
            httpClient = new HttpClient(sslContextFactory);
            httpClient.start();
            // ContentResponse
            ContentResponse response = httpClient.newRequest(host, serverPort)
                    .path(path)
                    .scheme(scheme)
                    .send();
            int status = response.getStatus();
            Assert.assertEquals(HttpServletResponse.SC_OK, status);
            SSLSessionContext clientSessionContext = sslContextFactory
                    .getSslContext()
                    .getClientSessionContext();
            Enumeration<byte[]> ids = clientSessionContext.getIds();
            SSLSession session = clientSessionContext.getSession(ids.nextElement());
            Assert.assertEquals(protocol, session.getProtocol());
            Assert.assertEquals(cipherSuite, session.getCipherSuite());
        } finally {
            if (httpClient != null) {
                httpClient.stop();
            }
        }
    }

    private static SslContextFactory createClientSslContextFactory(String protocol, String cipherSuite) {
        SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
        sslContextFactory.setProtocol(GMTLS_PROTOCOL);
        sslContextFactory.setKeyStorePath(CLIENT_KEYSTORE_PATH);
        sslContextFactory.setKeyStorePassword(CLIENT_KEYSTORE_PASSWORD);
        sslContextFactory.setTrustStorePath(SERVER_TRUSTSTORE_PATH);
        sslContextFactory.setTrustStorePassword(SERVER_TRUSTSTORE_PASSWORD);
        sslContextFactory.setIncludeProtocols(protocol);
        sslContextFactory.setIncludeCipherSuites(cipherSuite);
        return sslContextFactory;
    }
}
