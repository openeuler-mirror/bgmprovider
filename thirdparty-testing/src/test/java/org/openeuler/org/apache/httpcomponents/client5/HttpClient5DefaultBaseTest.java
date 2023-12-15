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

package org.openeuler.org.apache.httpcomponents.client5;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.impl.bootstrap.HttpServer;
import org.apache.hc.core5.http.impl.bootstrap.ServerBootstrap;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.StatusLine;
import org.junit.Assert;

import org.junit.BeforeClass;
import org.openeuler.commons.BaseTest;
import org.openeuler.commons.TestUtils;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.io.IOException;

public class HttpClient5DefaultBaseTest extends BaseTest {
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String PASSWORD = "12345678";

    private HttpServer httpServer;

    private CloseableHttpClient httpClient;

    @BeforeClass
    public static void beforeClass() {
        System.setProperty("javax.net.debug", "all");
        System.setProperty("jdk.tls.server.protocols", "GMTLS,TLSv1.2,TLSv1.3");
        String keyStorePath = TestUtils.getPath("server.keystore");
        Assert.assertNotNull(keyStorePath);
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStoreType", KEYSTORE_TYPE);
        System.setProperty("javax.net.ssl.keyStorePassword", PASSWORD);

        String trustStorePath = TestUtils.getPath("server.truststore");
        Assert.assertNotNull(trustStorePath);
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStoreType", KEYSTORE_TYPE);
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);
    }

    protected void prepare(String tlsVersion, boolean clientAuth)
            throws Exception {
        System.setProperty("jdk.tls.client.protocols", tlsVersion);
        SSLContext sslContext = SSLContext.getDefault();
        httpServer = ServerBootstrap.bootstrap()
                .setSslContext(sslContext)
                .setSslSetupHandler(new TestSSLServerSetupHandler(clientAuth))
                .register("/testDefault/*", new TestHttpRequestHandler())
                .create();
        httpServer.start();

        PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .useSystemProperties()
                .build();

        httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .useSystemProperties()
                .build();
    }

    protected void test(String tlsVersion, boolean clientAuth) throws Exception {
        prepare(tlsVersion, clientAuth);
        HttpHost httpHost = new HttpHost("https", "localhost", httpServer.getLocalPort());
        HttpClientContext clientContext = HttpClientContext.create();
        HttpGet httpGet = new HttpGet("/testDefault/");
        httpClient.execute(httpHost, httpGet, clientContext, new HttpClientResponseHandler<Object>() {
            @Override
            public Object handleResponse(ClassicHttpResponse response) throws HttpException, IOException {
                System.out.println("----------------------------------------");
                System.out.println(httpGet + "->" + new StatusLine(response));
                EntityUtils.consume(response.getEntity());
                SSLSession sslSession = clientContext.getSSLSession();
                Assert.assertNotNull(sslSession);

                System.out.println("SSL protocol: " + sslSession.getProtocol());
                System.out.println("SSL cipher suite: " + sslSession.getCipherSuite());
                Assert.assertEquals(tlsVersion, sslSession.getProtocol());
                return null;
            }
        });
    }
}
