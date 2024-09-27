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

package org.openeuler.sdf.jsse.gmtls;

import org.junit.Assert;
import org.openeuler.BGMJCEProvider;
import org.openeuler.BGMJSSEProvider;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.sdf.commons.util.SDFTestUtil;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;


public class SDFSSLSocketTestBase {
    private static final int TIMEOUT = 30000;

    private static final String HOST = "localhost";

    private static final String HELLO_SERVER = "hello server";
    private static final String HELLO_CLIENT = "hello client";

    // keystore directory path
    private static final String KEYSTORE_DIR_PATH = "gmtls/";

    // server keystore path
    private static final String SERVER_KEYSTORE_PATH = SDFTestUtil.getResource(KEYSTORE_DIR_PATH + "server.keystore");

    // server truststore path
    private static final String SERVER_TRUSTSTORE_PATH = SDFTestUtil.getResource(KEYSTORE_DIR_PATH + "client.truststore");

    // client keystore path
    private static final String CLIENT_KEYSTORE_PATH = SDFTestUtil.getResource(KEYSTORE_DIR_PATH + "client.keystore");

    // client truststore path
    private static final String CLIENT_TRUSTSTORE_PATH = SDFTestUtil.getResource(KEYSTORE_DIR_PATH + "server.truststore");

    // default keystore password
    private static final char[] DEFAULT_PASSWORD = "12345678".toCharArray();

    // KeyStore type
    private static final String KEYSTORE_TYPE = "PKCS12";

    // KeyManagerFactory algorithm
    protected static final String KMF_ALGORITHM = KeyManagerFactory.getDefaultAlgorithm();

    // TrustManagerFactory algorithm
    private static final String TMF_ALGORITHM = TrustManagerFactory.getDefaultAlgorithm();

    // server keystore parameters
    private static final KeyStoreParameters SERVER_KS_PARAM = new KeyStoreParameters(
            KEYSTORE_TYPE, SERVER_KEYSTORE_PATH, DEFAULT_PASSWORD);

    // server truststore parameters
    private static final KeyStoreParameters SERVER_TS_PARAM = new KeyStoreParameters(
            KEYSTORE_TYPE, SERVER_TRUSTSTORE_PATH, DEFAULT_PASSWORD);

    // client keystore parameters
    private static final KeyStoreParameters CLIENT_KS_PARAM = new KeyStoreParameters(
            KEYSTORE_TYPE, CLIENT_KEYSTORE_PATH, DEFAULT_PASSWORD);

    // client truststore parameters
    private static final KeyStoreParameters CLIENT_TS_PARAM = new KeyStoreParameters(
            KEYSTORE_TYPE, CLIENT_TRUSTSTORE_PATH, DEFAULT_PASSWORD);

    static final class KeyStoreParameters {
        private final String type;
        private final String path;
        private final char[] password;
        private String algorithm;


        KeyStoreParameters(String type, String path, char[] password, String algorithm) {
            this.type = type;
            this.path = path;
            this.password = password;
            this.algorithm = algorithm;
        }

        KeyStoreParameters(String type, String path, char[] password) {
            this(type, path, password, null);
        }

        KeyStoreParameters(KeyStoreParameters parameters) {
            this(parameters.type, parameters.path, parameters.password, parameters.getAlgorithm());
        }

        KeyStoreParameters(KeyStoreParameters parameters, String algorithm) {
            this(parameters.type, parameters.path, parameters.password, algorithm);
        }

        public String getType() {
            return type;
        }

        public String getPath() {
            return path;
        }

        public char[] getPassword() {
            return password;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getAlgorithm() {
            return algorithm;
        }
    }

    protected static void init() {
        setSDFProperties();
        insertProviders();
    }

    private static void setSDFProperties() {
        System.setProperty("sdf.useEncDEK", "true");
        System.setProperty("sdf.defaultKEKId", new String(SDFTestUtil.getTestKekId()));
        System.setProperty("sdf.defaultRegionId", new String(SDFTestUtil.getTestRegionId()));
        System.setProperty("sdf.defaultCdpId", new String(SDFTestUtil.getTestCdpId()));
    }

    private static void insertProviders() {
        Security.insertProviderAt(new SDFProvider(), 1);
        Security.insertProviderAt(new BGMJSSEProvider(), 2);
    }

    private static KeyStore createKeyStore(KeyStoreParameters keyStoreParameters)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore;
        try (InputStream ksInputStream = new FileInputStream(keyStoreParameters.getPath())) {
            keyStore = KeyStore.getInstance(keyStoreParameters.getType());
            keyStore.load(ksInputStream, keyStoreParameters.getPassword());
        } catch (IOException e) {
            throw new RuntimeException("createKeyStore failed", e);
        }
        return keyStore;
    }

    private static KeyManagerFactory createKeyManagerFactory(String algorithm,
                                                             KeyStore keyStore, char[] keyStorePassword)
            throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
        keyManagerFactory.init(keyStore, keyStorePassword);
        return keyManagerFactory;
    }

    private static TrustManagerFactory createTrustManagerFactory(String algorithm,
                                                                 KeyStore trustStore)
            throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
        trustManagerFactory.init(trustStore);
        return trustManagerFactory;
    }

    public static SSLContext createSSLContext(Provider provider, String contextProtocol,
                                              KeyManager[] km, TrustManager[] tm, SecureRandom random)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext;
        if (provider != null) {
            sslContext = SSLContext.getInstance(contextProtocol, provider);
        } else {
            sslContext = SSLContext.getInstance(contextProtocol);
        }
        sslContext.init(km, tm, random);
        return sslContext;
    }

    public static SSLContext createSSLContext(Provider provider,
                                              String contextProtocol, KeyStoreParameters keyStoreParameters,
                                              KeyStoreParameters trustStoreParameters, SecureRandom random)
            throws CertificateException, KeyStoreException, NoSuchAlgorithmException,
            UnrecoverableKeyException, KeyManagementException {
        KeyManager[] keyManagers = null;
        if (keyStoreParameters != null) {
            KeyStore keyStore = createKeyStore(keyStoreParameters);

            KeyManagerFactory keyManagerFactory = createKeyManagerFactory(
                    keyStoreParameters.getAlgorithm(), keyStore, keyStoreParameters.getPassword());
            keyManagers = keyManagerFactory.getKeyManagers();
        }

        TrustManager[] trustManagers = null;
        if (trustStoreParameters != null) {
            KeyStore trustStore = createKeyStore(trustStoreParameters);
            TrustManagerFactory trustManagerFactory = createTrustManagerFactory(
                    trustStoreParameters.getAlgorithm(), trustStore);
            trustManagers = trustManagerFactory.getTrustManagers();
        }

        return createSSLContext(provider, contextProtocol, keyManagers, trustManagers, random);
    }

    enum Status {
        NORMAL,
        SERVER_RENEGOTIATE,
        CLIENT_RENEGOTIATE,
        SESSION_RESUMPTION_START,
        SESSION_RESUMPTION_REUSE
    }

    static class ReqParameters {

        // server port
        protected int serverPort;
        // SSLContext protocol
        protected String contextProtocol;

        // enable protocols
        protected String[] enableProtocols;

        // enable cipher suites
        protected String[] enableCipherSuites;

        // status
        protected Status status;

        // KeyManagerFactory algorithm
        protected String kmfAlgorithm;

        // TrustManagerFactory algorithm
        protected String tmfAlgorithm;

        // clientAuthType
        protected boolean clientAuthType;

        protected Provider clientProvider;

        protected Provider serverProvider;

        protected String expectedProtocol;

        protected String expectedCiphersuite;

        protected SSLContext sslContext;

        protected KeyStoreParameters keyStoreParameters;

        protected KeyStoreParameters trustStoreParameters;

        public int getServerPort() {
            return serverPort;
        }

        public String getContextProtocol() {
            return contextProtocol;
        }

        public String[] getEnableProtocols() {
            return enableProtocols;
        }

        public String[] getEnableCipherSuites() {
            return enableCipherSuites;
        }

        public Status getStatus() {
            return status;
        }

        public String getKmfAlgorithm() {
            return kmfAlgorithm;
        }

        public String getTmfAlgorithm() {
            return tmfAlgorithm;
        }

        public boolean getClientAuthType() {
            return clientAuthType;
        }

        public Provider getServerProvider() {
            return serverProvider;
        }

        public Provider getClientProvider() {
            return clientProvider;
        }

        public String getExpectedProtocol() {
            return expectedProtocol;
        }

        public String getExpectedCiphersuite() {
            return expectedCiphersuite;
        }

        public SSLContext getSslContext() {
            return sslContext;
        }

        public KeyStoreParameters getKeyStoreParameters() {
            return keyStoreParameters;
        }

        public KeyStoreParameters getTrustStoreParameters() {
            return trustStoreParameters;
        }

        ReqParameters(Builder builder) {
            this.contextProtocol = builder.contextProtocol;
            this.enableProtocols = builder.enableProtocols;
            this.enableCipherSuites = builder.enableCipherSuites;
            this.status = builder.status;
            this.kmfAlgorithm = builder.kmfAlgorithm;
            this.tmfAlgorithm = builder.tmfAlgorithm;
            this.clientAuthType = builder.clientAuthType;
            this.clientProvider = builder.clientProvider;
            this.serverProvider = builder.serverProvider;
            this.expectedProtocol = builder.expectedProtocol;
            this.expectedCiphersuite = builder.expectedCiphersuite;
            this.sslContext = builder.sslContext;
            this.serverPort = builder.serverPort;
            this.keyStoreParameters = builder.keyStoreParameters;
            this.trustStoreParameters = builder.trustStoreParameters;
        }

        static class Builder {
            // server port
            private int serverPort;
            // SSLContext protocol
            private String contextProtocol = "TLS";

            // enable protocols
            private String[] enableProtocols;

            // enable cipher suites
            private String[] enableCipherSuites;

            // status
            private Status status = Status.NORMAL;

            // KeyManagerFactory algorithm
            private String kmfAlgorithm = KMF_ALGORITHM;

            // TrustManagerFactory algorithm
            private String tmfAlgorithm = TMF_ALGORITHM;

            // clientAuthType
            private boolean clientAuthType = false;

            // serverProvider
            private Provider serverProvider;

            // clientProvider
            private Provider clientProvider;

            // expectedProtocol
            private String expectedProtocol;

            // expectedCiphersuite
            private String expectedCiphersuite;

            //sslContext for session resumption
            private SSLContext sslContext;

            // keystore parameters
            protected KeyStoreParameters keyStoreParameters;

            // truststore parameters
            protected KeyStoreParameters trustStoreParameters;

            Builder serverPort(int serverPort) {
                this.serverPort = serverPort;
                return this;
            }

            Builder contextProtocol(String contextProtocol) {
                this.contextProtocol = contextProtocol;
                return this;
            }

            Builder enableProtocols(String[] enableProtocols) {
                this.enableProtocols = enableProtocols;
                return this;
            }

            Builder enableCipherSuites(String[] enableCipherSuites) {
                this.enableCipherSuites = enableCipherSuites;
                return this;
            }

            Builder status(Status status) {
                this.status = status;
                return this;
            }

            Builder kmfAlgorithm(String kmfAlgorithm) {
                this.kmfAlgorithm = kmfAlgorithm;
                return this;
            }

            Builder tmfAlgorithm(String tmfAlgorithm) {
                this.tmfAlgorithm = tmfAlgorithm;
                return this;
            }

            Builder clientAuthType(boolean clientAuthType) {
                this.clientAuthType = clientAuthType;
                return this;
            }

            Builder sslContext(SSLContext sslContext) {
                this.sslContext = sslContext;
                return this;
            }

            ReqParameters build() {
                return new ReqParameters(this);
            }

            Builder clientProvider(Provider clientProvider) {
                this.clientProvider = clientProvider;
                return this;
            }

            Builder serverProvider(Provider serverProvider) {
                this.serverProvider = serverProvider;
                return this;
            }

            Builder expectedProtocol(String expectedProtocol) {
                this.expectedProtocol = expectedProtocol;
                return this;
            }

            Builder expectedCiphersuite(String expectedCiphersuite) {
                this.expectedCiphersuite = expectedCiphersuite;
                return this;
            }

            Builder keyStoreParameters(KeyStoreParameters keyStoreParameters) {
                this.keyStoreParameters = keyStoreParameters;
                return this;
            }

            Builder trustStoreParameters(KeyStoreParameters trustStoreParameters) {
                this.trustStoreParameters = trustStoreParameters;
                return this;
            }

        }
    }


    /**
     * Handle Thread
     */
    static abstract class HandleThread implements Runnable {
        private ReqParameters reqParameters;

        private Throwable throwable;

        public void setThrowable(Throwable throwable) {
            this.throwable = throwable;
        }

        public Throwable getThrowable() {
            return throwable;
        }

        // ready
        private volatile boolean ready = false;

        public void setReady(boolean ready) {
            this.ready = ready;
        }

        public boolean isReady() {
            return ready;
        }

        public HandleThread(ReqParameters reqParameters) {
            this.reqParameters = reqParameters;
        }

        public ReqParameters getReqParameters() {
            return reqParameters;
        }

        public abstract void handle();

        public abstract void handleMessage(DataOutputStream outputStream, DataInputStream inputStream)
                throws IOException;

        public void handleRenegotiate(DataOutputStream outputStream, DataInputStream inputStream,
                                      SSLSocket sslSocket, boolean isActive) throws IOException {
            for (int i = 0; i < 10; i++) {
                handleMessage(outputStream, inputStream);
            }
            if (isActive) {
                sslSocket.getSession().invalidate();
                sslSocket.startHandshake();
            }
            for (int i = 0; i < 10; i++) {
                handleMessage(outputStream, inputStream);
            }
        }

        @Override
        public void run() {
            handle();
        }
    }

    /**
     * Server
     */
    static class ServerThread extends HandleThread {

        public ServerThread(ReqParameters reqParameters) {
            super(reqParameters);
        }

        @Override
        public void handle() {
            handleServer(getReqParameters());
        }

        private void handleServer(ReqParameters reqParameters) {
            Thread.currentThread().setName("server");
            String contextProtocol = reqParameters.getContextProtocol();
            String[] enableCipherSuites = reqParameters.getEnableCipherSuites();
            String[] enableProtocols = reqParameters.getEnableProtocols();
            Status status = reqParameters.getStatus();
            boolean clientAuthType = reqParameters.getClientAuthType();
            KeyStoreParameters keyStoreParameters = reqParameters.getKeyStoreParameters();
            KeyStoreParameters trustStoreParameters = reqParameters.getTrustStoreParameters();
            SSLContext sslContext;
            byte[] resumptionSessionId = null;
            try {
                if (keyStoreParameters == null) {
                    keyStoreParameters = new KeyStoreParameters(SERVER_KS_PARAM,
                            reqParameters.getKmfAlgorithm());
                }

                if (trustStoreParameters == null) {
                    trustStoreParameters = new KeyStoreParameters(SERVER_TS_PARAM,
                            reqParameters.getTmfAlgorithm());
                }
                sslContext = createSSLContext(reqParameters.getServerProvider(), contextProtocol, keyStoreParameters, trustStoreParameters, new SecureRandom());
            } catch (Throwable e) {
                setReady(true);
                setThrowable(e);
                throw new RuntimeException("createSSLContext failed", e);
            }

            ServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = null;
            SSLSocket sslSocket = null;
            try {
                serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(reqParameters.serverPort);
                reqParameters.serverPort = serverSocket.getLocalPort();
                System.out.println("serverPort:" +  reqParameters.serverPort);
                if (enableCipherSuites != null && enableCipherSuites.length != 0) {
                    serverSocket.setEnabledCipherSuites(enableCipherSuites);
                }
                if (enableProtocols != null && enableProtocols.length != 0) {
                    serverSocket.setEnabledProtocols(enableProtocols);
                }
                setReady(true);
                sslSocket = (SSLSocket) serverSocket.accept();
                sslSocket.setNeedClientAuth(clientAuthType);
                sslSocket.setSoTimeout(TIMEOUT);

                if (Status.SESSION_RESUMPTION_START.equals(status)) {
                    resumptionSessionId = sslSocket.getSession().getId();
                }
                DataInputStream dataInputStream = new DataInputStream(sslSocket.getInputStream());
                DataOutputStream dataOutputStream = new DataOutputStream(sslSocket.getOutputStream());
                if (Status.SERVER_RENEGOTIATE.equals(status)) {
                    handleRenegotiate(dataOutputStream, dataInputStream, sslSocket, true);
                } else if (Status.CLIENT_RENEGOTIATE.equals(status)) {
                    handleRenegotiate(dataOutputStream, dataInputStream, null, false);
                } else {
                    handleMessage(dataOutputStream, dataInputStream);
                }
            } catch (Throwable e) {
                setReady(true);
                setThrowable(e);
                throw new RuntimeException(e);
            } finally {
                if (serverSocket != null) {
                    try {
                        if (!Status.SESSION_RESUMPTION_START.equals(status)) {
                            serverSocket.close();
                        }
                    } catch (IOException e) {
                        System.err.println("handleServer : " + e.getMessage());
                        throw new RuntimeException(e);
                    }
                }
                if (sslSocket != null) {
                    try {
                        sslSocket.close();
                    } catch (IOException e) {
                        System.err.println("handleServer : " + e.getMessage());
                        throw new RuntimeException(e);
                    }
                }
            }
            if (Status.SESSION_RESUMPTION_START.equals(status)) {
                try {
                    sslSocket = (SSLSocket) serverSocket.accept();
                    sslSocket.setNeedClientAuth(clientAuthType);

                    // When using TLSv1.3, the server will copy and create a new handshake Session
                    // when creating NewSessionTicket, and the SessionId is also new.
                    if (!"TLSv1.3".equals(sslSocket.getSession().getProtocol())) {
                        byte[] sessionId = sslSocket.getSession().getId();
                        Assert.assertArrayEquals(sessionId, resumptionSessionId);
                    }

                    DataInputStream dataInputStream = new DataInputStream(sslSocket.getInputStream());
                    DataOutputStream dataOutputStream = new DataOutputStream(sslSocket.getOutputStream());
                    handleMessage(dataOutputStream, dataInputStream);

                } catch (Throwable e) {
                    setReady(true);
                    System.err.println("handleServer : " + e.getMessage());
                    throw new RuntimeException(e);
                } finally {
                    if (serverSocket != null) {
                        try {
                            serverSocket.close();
                        } catch (IOException e) {
                            System.err.println("handleServer : " + e.getMessage());
                            throw new RuntimeException(e);
                        }
                    }
                    if (sslSocket != null) {
                        try {
                            sslSocket.close();
                        } catch (IOException e) {
                            System.err.println("handleServer : " + e.getMessage());
                            throw new RuntimeException(e);
                        }
                    }
                }
            }
        }


        @Override
        public void handleMessage(DataOutputStream dataOutputStream, DataInputStream dataInputStream)
                throws IOException {
            String message = dataInputStream.readUTF();
            System.out.println("server receive : " + message);
            dataOutputStream.writeUTF(HELLO_CLIENT);
            System.out.println("server send : " + HELLO_CLIENT);
            dataOutputStream.flush();
        }
    }

    /**
     * Client
     */
    static class ClientThread extends HandleThread {

        private SSLContext resumpotionContext;

        public SSLContext getResumpotionContext() {
            return resumpotionContext;
        }

        public ClientThread(ReqParameters reqParameters) {
            super(reqParameters);
        }

        @Override
        public void handle() {
            handleClient(getReqParameters());
        }

        @Override
        public void handleMessage(DataOutputStream outputStream, DataInputStream inputStream)
                throws IOException {
            outputStream.writeUTF(HELLO_SERVER);
            System.out.println("client send : " + HELLO_SERVER);
            outputStream.flush();

            String message = inputStream.readUTF();
            System.out.println("client receive : " + message);
        }

        private void handleClient(ReqParameters reqParameters) {
            Thread.currentThread().setName("client");
            String contextProtocol = reqParameters.getContextProtocol();
            String[] enableCipherSuites = reqParameters.getEnableCipherSuites();
            String[] enableProtocols = reqParameters.getEnableProtocols();
            Status status = reqParameters.getStatus();
            KeyStoreParameters keyStoreParameters = reqParameters.getKeyStoreParameters();
            KeyStoreParameters trustStoreParameters = reqParameters.getTrustStoreParameters();
            SSLContext sslContext;
            try {
                if (Status.SESSION_RESUMPTION_REUSE.equals(status)) {
                    sslContext = reqParameters.getSslContext();
                } else {
                    if (keyStoreParameters == null) {
                        keyStoreParameters = new KeyStoreParameters(CLIENT_KS_PARAM,
                                reqParameters.getKmfAlgorithm());
                    }
                    if (trustStoreParameters == null) {
                        trustStoreParameters = new KeyStoreParameters(CLIENT_TS_PARAM,
                                reqParameters.getTmfAlgorithm());
                    }
                    sslContext = createSSLContext(reqParameters.getClientProvider(), contextProtocol, keyStoreParameters, trustStoreParameters, new SecureRandom());
                    if (Status.SESSION_RESUMPTION_START.equals(status)) {
                        resumpotionContext = sslContext;
                    }
                }
            } catch (Throwable e) {
                setThrowable(e);
                System.err.println(e.getMessage());
                throw new RuntimeException(e);
            }

            SocketFactory socketFactory = sslContext.getSocketFactory();
            SSLSocket sslSocket = null;
            try {
                sslSocket = (SSLSocket) socketFactory.createSocket(HOST, reqParameters.serverPort);

                if (enableCipherSuites != null && enableCipherSuites.length != 0) {
                    sslSocket.setEnabledCipherSuites(enableCipherSuites);
                }
                if (enableProtocols != null && enableProtocols.length != 0) {
                    sslSocket.setEnabledProtocols(enableProtocols);
                }
                sslSocket.setSoTimeout(TIMEOUT);

                DataOutputStream dataOutputStream = new DataOutputStream(sslSocket.getOutputStream());
                DataInputStream dataInputStream = new DataInputStream(sslSocket.getInputStream());

                if (Status.SERVER_RENEGOTIATE.equals(status)) {
                    handleRenegotiate(dataOutputStream, dataInputStream, null, false);
                } else if (Status.CLIENT_RENEGOTIATE.equals(status)) {
                    handleRenegotiate(dataOutputStream, dataInputStream, sslSocket, true);
                } else {
                    handleMessage(dataOutputStream, dataInputStream);
                }
                if (reqParameters.getExpectedProtocol() != null) {
                    Assert.assertEquals(reqParameters.getExpectedProtocol(), sslSocket.getSession().getProtocol());
                }
                if (reqParameters.getExpectedCiphersuite() != null) {
                    Assert.assertEquals(reqParameters.getExpectedCiphersuite(), sslSocket.getSession().getCipherSuite());
                }
            } catch (Throwable e) {
                setThrowable(e);
                throw new RuntimeException(e);
            } finally {
                if (sslSocket != null) {
                    try {
                        sslSocket.close();
                    } catch (IOException e) {
                        System.err.println("handleClient : " + e.getMessage());
                        throw new RuntimeException(e);
                    }
                }
            }
        }
    }

    protected void test(ReqParameters serverParams, ReqParameters clientParams) {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        ServerThread serverThread = null;
        ClientThread clientThread = null;
        try {
            serverThread = new ServerThread(serverParams);
            Future<?> serverFuture = executorService.submit(serverThread);
            while (!serverThread.isReady()) {
                Thread.sleep(10L);
            }
            clientParams.serverPort = serverParams.serverPort;
            clientThread = new ClientThread(clientParams);
            Future<?> clientFuture = executorService.submit(clientThread);
            clientFuture.get();
            if (Status.SESSION_RESUMPTION_START.equals(clientParams.getStatus())) {
                Thread.sleep(100L);
                Assert.assertNotNull(clientThread.getResumpotionContext());
                ReqParameters clientResumptionParams = new ReqParameters.Builder()
                        .sslContext(clientThread.getResumpotionContext())
                        .enableProtocols(clientParams.enableProtocols)
                        .enableCipherSuites(clientParams.getEnableCipherSuites())
                        .status(Status.SESSION_RESUMPTION_REUSE)
                        .serverPort(clientParams.serverPort)
                        .build();

                ClientThread resumptionClientThread = new ClientThread(clientResumptionParams);
                Future<?> resumptionClientFuture = executorService.submit(resumptionClientThread);
                resumptionClientFuture.get();
            }
            serverFuture.get();
        } catch (Throwable e) {
            Throwable throwable = getThrowable(serverThread);
            if (throwable != null) {
                throw new RuntimeException(throwable);
            }
            throwable = getThrowable(clientThread);
            if (throwable != null) {
                throw new RuntimeException(throwable);
            }
            throw new RuntimeException(e);
        } finally {
            executorService.shutdown();
        }
    }

    private Throwable getThrowable(HandleThread handleThread) {
        if (handleThread == null) {
            return null;
        }
        Throwable throwable = handleThread.getThrowable();
        if (throwable instanceof ExceptionInInitializerError) {
            ExceptionInInitializerError error = (ExceptionInInitializerError) throwable;
            return error.getException();
        } else {
            return throwable;
        }
    }

    private void test(Provider serverProvider, Provider clientProvider,
                      String serverContextProtocol, String[] serverEnableProtocols, String[] serverEnableCipherSuites,
                      String clientContextProtocol, String[] clientEnableProtocols, String[] clientEnableCipherSuites,
                      Status status, String kmfAlgorithm, boolean clientAuthType,
                      String expectedProtocol, String expectedCiphersuite) {
        if (kmfAlgorithm == null || kmfAlgorithm.isEmpty()) {
            kmfAlgorithm = KMF_ALGORITHM;
        }
        ReqParameters serverParams = new ReqParameters.Builder()
                .contextProtocol(serverContextProtocol)
                .enableProtocols(serverEnableProtocols)
                .enableCipherSuites(serverEnableCipherSuites)
                .kmfAlgorithm(kmfAlgorithm)
                .status(status)
                .clientAuthType(clientAuthType)
                .serverProvider(serverProvider)
                .build();

        ReqParameters clientParams = new ReqParameters.Builder()
                .contextProtocol(clientContextProtocol)
                .enableProtocols(clientEnableProtocols)
                .enableCipherSuites(clientEnableCipherSuites)
                .kmfAlgorithm(kmfAlgorithm)
                .status(status)
                .clientProvider(clientProvider)
                .expectedProtocol(expectedProtocol)
                .expectedCiphersuite(expectedCiphersuite)
                .build();
        test(serverParams, clientParams);
    }

    protected void test(String serverContextProtocol, String[] serverEnableProtocols, String[] serverEnableCipherSuites,
                        String clientContextProtocol, String[] clientEnableProtocols, String[] clientEnableCipherSuites,
                        Status status, String kmfAlgorithm) {
        test(null, null, serverContextProtocol,
                serverEnableProtocols, serverEnableCipherSuites,
                clientContextProtocol, clientEnableProtocols, clientEnableCipherSuites, status, kmfAlgorithm,
                false, null, null);
    }

    protected void test(String serverContextProtocol, String[] serverEnableProtocols, String[] serverEnableCipherSuites,
                        String clientContextProtocol, String[] clientEnableProtocols, String[] clientEnableCipherSuites,
                        Status status) {
        test(serverContextProtocol, serverEnableProtocols, serverEnableCipherSuites,
                clientContextProtocol, clientEnableProtocols, clientEnableCipherSuites, status, KMF_ALGORITHM);
    }

    protected void test(String serverContextProtocol, String[] serverEnableProtocols, String[] serverEnableCipherSuites,
                        String clientContextProtocol, String[] clientEnableProtocols, String[] clientEnableCipherSuites,
                        String kmfAlgorithm) {
        test(serverContextProtocol, serverEnableProtocols, serverEnableCipherSuites,
                clientContextProtocol, clientEnableProtocols, clientEnableCipherSuites, Status.NORMAL, kmfAlgorithm);
    }

    protected void test(String serverContextProtocol, String[] serverEnableProtocols, String[] serverEnableCipherSuites,
                        String clientContextProtocol, String[] clientEnableProtocols, String[] clientEnableCipherSuites) {
        test(serverContextProtocol, serverEnableProtocols, serverEnableCipherSuites,
                clientContextProtocol, clientEnableProtocols, clientEnableCipherSuites, Status.NORMAL);
    }

    protected void test(String serverContextProtocol, String[] serverEnableProtocols, String[] serverEnableCipherSuites,
                        String clientContextProtocol, String[] clientEnableProtocols, String[] clientEnableCipherSuites,
                        boolean clientAuthType) {
        test(null, null, serverContextProtocol, serverEnableProtocols, serverEnableCipherSuites,
                clientContextProtocol, clientEnableProtocols, clientEnableCipherSuites,
                Status.NORMAL, KMF_ALGORITHM, clientAuthType, null, null);
    }

    protected void test(String serverContextProtocol, String[] serverEnableProtocols, String[] serverEnableCipherSuites,
                        String clientContextProtocol, String[] clientEnableProtocols, String[] clientEnableCipherSuites,
                        boolean clientAuthType, String expectProtocol, String expectCipherSuite) {
        test(null, null, serverContextProtocol, serverEnableProtocols, serverEnableCipherSuites,
                clientContextProtocol, clientEnableProtocols, clientEnableCipherSuites,
                Status.NORMAL, KMF_ALGORITHM, clientAuthType, expectProtocol, expectCipherSuite);
    }

    protected void test(String serverContextProtocol, String[] serverEnableProtocols, String[] serverEnableCipherSuites,
                        String clientContextProtocol, String[] clientEnableProtocols, String[] clientEnableCipherSuites,
                        String expectedProtocol, String expectedCipherSuite) {
        test(null, null, serverContextProtocol, serverEnableProtocols, serverEnableCipherSuites,
                clientContextProtocol, clientEnableProtocols, clientEnableCipherSuites,
                Status.NORMAL, KMF_ALGORITHM, false, expectedProtocol, expectedCipherSuite);
    }

    protected void test(Provider serverProvider, Provider clientProvider,
                        String serverContextProtocol, String[] serverEnableProtocols, String[] serverEnableCipherSuites,
                        String clientContextProtocol, String[] clientEnableProtocols, String[] clientEnableCipherSuites,
                        String expectedProtocol, String expectedCipherSuite) {
        test(serverProvider, clientProvider, serverContextProtocol, serverEnableProtocols, serverEnableCipherSuites,
                clientContextProtocol, clientEnableProtocols, clientEnableCipherSuites,
                Status.NORMAL, KMF_ALGORITHM, false, expectedProtocol, expectedCipherSuite);
    }
}
