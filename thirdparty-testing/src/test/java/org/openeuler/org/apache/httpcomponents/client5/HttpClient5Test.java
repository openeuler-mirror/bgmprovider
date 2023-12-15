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
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.impl.bootstrap.HttpServer;
import org.apache.hc.core5.http.impl.bootstrap.ServerBootstrap;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;
import org.junit.After;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.openeuler.commons.BaseTest;
import org.openeuler.commons.TestUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class HttpClient5Test extends BaseTest {
    private static final char[] PASSWORD = "12345678".toCharArray();
    private String tlsVersion;
    private boolean clientAuth;
    private HttpServer httpServer;
    private CloseableHttpClient httpClient;

    public HttpClient5Test(String tlsVersion, boolean clientAuth) throws Exception {
        this.tlsVersion = tlsVersion;
        this.clientAuth = clientAuth;
        init(tlsVersion, clientAuth);
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {"GMTLS", true},
                {"TLSv1.2", true},
                {"TLSv1.3", true},
                {"GMTLS", false},
                {"TLSv1.2", false},
                {"TLSv1.3", false}
        });
    }

    private void init(String tlsVersion, boolean clientAuth) throws Exception {
        SocketConfig socketConfig = SocketConfig.custom().setSoTimeout(Timeout.ofSeconds(30)).build();

        // Init server support GMTLS,TLSv1.2,TLSv1.3
        String serverKeyMaterialPath = TestUtils.getPath("server.keystore");
        Assert.assertNotNull(serverKeyMaterialPath);
        String serverTrustMaterialPath = TestUtils.getPath("client.truststore");
        Assert.assertNotNull(serverTrustMaterialPath);
        SSLContext serverSSLContext = SSLContexts.custom()
                .loadKeyMaterial(new File(serverKeyMaterialPath), PASSWORD, PASSWORD)
                .loadTrustMaterial(new File(serverTrustMaterialPath), PASSWORD)
                .build();
        httpServer = ServerBootstrap.bootstrap()
                .setSocketConfig(socketConfig)
                .setSslContext(serverSSLContext)
                .setSslSetupHandler(new TestSSLServerSetupHandler(clientAuth))
                .register("/test/*", new TestHttpRequestHandler())
                .create();

        // Init client
        String clientKeyMaterialPath = TestUtils.getPath("client.keystore");
        Assert.assertNotNull(clientKeyMaterialPath);
        String clientTrustMaterialPath = TestUtils.getPath("server.truststore");
        Assert.assertNotNull(clientTrustMaterialPath);
        SSLContext clientSSLContext = SSLContexts.custom()
                .loadKeyMaterial(new File(clientKeyMaterialPath), PASSWORD, PASSWORD)
                .loadTrustMaterial(new File(clientTrustMaterialPath), PASSWORD)
                .build();

        SSLConnectionSocketFactory sslConnectionSocketFactory = SSLConnectionSocketFactoryBuilder.create()
                .setSslContext(clientSSLContext)
                .setTlsVersions(tlsVersion)  // ssl protocol version
                .build();
        PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(sslConnectionSocketFactory)
                .setDefaultTlsConfig(TlsConfig.custom()
                        .setHandshakeTimeout(Timeout.ofSeconds(30))
                        .build())
                .build();
        httpClient = HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    @Test
    public void test() throws Exception {
        httpServer.start();

        HttpHost httpHost = new HttpHost("https", "localhost", httpServer.getLocalPort());
        HttpClientContext clientContext = HttpClientContext.create();
        HttpGet httpGet = new HttpGet("/test/");
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

    @After
    public void shutdown() throws Exception {
        System.out.println("shutdown");
        if (httpClient != null) {
            httpClient.close();
        }
        if (httpServer != null) {
            httpServer.close();
        }
    }
}
