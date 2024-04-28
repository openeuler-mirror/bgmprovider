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

package org.openeuler.io.netty;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.IdentityCipherSuiteFilter;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.ReferenceCountUtil;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMProvider;
import org.openeuler.commons.TestUtils;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.Security;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public class NettyGMTLSTest {
    private static final String trustStorePath = TestUtils.getPath("server.truststore");
    private static final String keyStorePath = TestUtils.getPath("server.keystore");
    private static final char[] PASSWORD = "12345678".toCharArray();

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMProvider(), 1);
    }

    @Test
    public void test() throws Throwable {
        testGMTLSHandshake();
    }

    private static TrustManager getTrustManager() throws Throwable {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fileInputStream = new FileInputStream(Objects.requireNonNull(trustStorePath))) {
            keyStore.load(fileInputStream, PASSWORD);
        }

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        return trustManagers[0];
    }


    private static KeyManager getKeyManager() throws Throwable {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fileInputStream = new FileInputStream(Objects.requireNonNull(keyStorePath))) {
            keyStore.load(fileInputStream, PASSWORD);
        }
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, PASSWORD);
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
        return keyManagers[0];
    }

    private static void testGMTLSHandshake()
            throws Throwable {
        // client
        TrustManager trustManager = getTrustManager();
        SslContext clientSslContext = SslContextBuilder.forClient()
                .trustManager(trustManager)
                .protocols("GMTLS")
                .ciphers(null, IdentityCipherSuiteFilter.INSTANCE_DEFAULTING_TO_SUPPORTED_CIPHERS)
                .build();
        SSLEngine clientEngine = clientSslContext.newEngine(UnpooledByteBufAllocator.DEFAULT);
        SslHandler clientSslHandler = new SslHandler(clientEngine);

        // server
        KeyManager keyManager = getKeyManager();
        SslContext serverSslContext = SslContextBuilder.forServer(keyManager)
                .protocols("GMTLS")
                .ciphers(null, IdentityCipherSuiteFilter.INSTANCE_DEFAULTING_TO_SUPPORTED_CIPHERS)
                .build();
        SSLEngine serverEngine = serverSslContext.newEngine(UnpooledByteBufAllocator.DEFAULT);
        SslHandler serverSslHandler = new SslHandler(serverEngine);

        EventLoopGroup group = new NioEventLoopGroup();
        Channel serverChannel = null;
        Channel clientChannel = null;
        try {
            // server channel
            serverChannel = new ServerBootstrap()
                    .group(group)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<Channel>() {
                        @Override
                        protected void initChannel(Channel channel) {
                            channel.pipeline().addLast(serverSslHandler);
                        }
                    })
                    .bind(new InetSocketAddress(0)).syncUninterruptibly().channel();

            // client channel
            ChannelFuture future = new Bootstrap()
                    .group(group)
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<Channel>() {
                        @Override
                        protected void initChannel(Channel channel) {
                            channel.pipeline().addLast(clientSslHandler);
                        }
                    }).connect(serverChannel.localAddress());
            clientChannel = future.syncUninterruptibly().channel();
            
            // test
            Assert.assertTrue(clientSslHandler.handshakeFuture().await().isSuccess());
            Assert.assertTrue(serverSslHandler.handshakeFuture().await().isSuccess());
            Assert.assertEquals("GMTLS", serverEngine.getSession().getProtocol());
        } finally {
            if (clientChannel != null) {
                clientChannel.close().syncUninterruptibly();
            }
            if (serverChannel != null) {
                serverChannel.close().syncUninterruptibly();
            }
            group.shutdownGracefully();
            ReferenceCountUtil.release(clientSslContext);
            ReferenceCountUtil.release(serverSslContext);
        }
    }
}
