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

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.junit.AfterClass;
import org.junit.Assert;
import org.openeuler.BGMProvider;
import org.openeuler.util.JavaVersionUtil;

import javax.net.ssl.*;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Properties;

import static org.openeuler.tomcat.TestUtils.arrayToString;
import static org.openeuler.tomcat.TestUtils.isEmpty;

public abstract class TomcatBaseTest {

    private static final Log log = LogFactory.getLog(TomcatBaseTest.class);
    private static final String MESSAGE = "Test GMTLS";
    private static final String DEFAULT_TEMP_DIR = "target/temp";
    private static final int READ_TIMEOUT = 1000;
    private static File tempDir;
    private static String testServletClass;

    static {
        try {
            init();
        } catch (IOException e) {
            throw new InternalError(e);
        }
    }

    private static void initTempDir() throws IOException {
        String tempPath = System.getProperty("tomcat.test.temp.dir", DEFAULT_TEMP_DIR);
        File tempBase = new File(tempPath);
        if (!tempBase.mkdirs() && !tempBase.isDirectory()) {
            Assert.fail("Unable to create " + tempPath + " directory for tests");
        }
        tempDir = Files.createTempDirectory(
                FileSystems.getDefault().getPath(tempBase.getAbsolutePath())
                , "test").toFile();
    }

    public static File getTempDir() {
        return tempDir;
    }

    public static void removeTempDir() {
        if (tempDir != null) {
            TestUtils.delete(tempDir);
            tempDir = null;
        }
    }

    private static void initTestServletClass() {
        String baseClass = TomcatBaseTest.class.getName();
        if (TestUtils.getTomcatVersion().isVersion10Plus()) {
            testServletClass = baseClass + "$TestServletForTomcat10Plus";
        } else {
            testServletClass = baseClass + "$TestServlet";
        }
    }

    // Test servlet for Tomcat 8.5.x , 9.0.x
    public static class TestServlet extends javax.servlet.http.HttpServlet {
        public TestServlet() {

        }

        @Override
        protected void doGet(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse resp)
                throws IOException {
            resp.getOutputStream().write(MESSAGE.getBytes());
        }
    }

    // Test servlet for Tomcat 10.0.x
    public static class TestServletForTomcat10Plus extends jakarta.servlet.http.HttpServlet {
        public TestServletForTomcat10Plus() {

        }

        @Override
        protected void doGet(jakarta.servlet.http.HttpServletRequest req, jakarta.servlet.http.HttpServletResponse resp)
                throws IOException {
            resp.getOutputStream().write(MESSAGE.getBytes());
        }
    }

    // Empty TrustManager , skip certificate check
    private static class EmptyTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    public static void init() throws IOException {
        if (!TestUtils.isSupportTLS()) {
            throw new IllegalStateException("Jre " + JavaVersionUtil.current() + "," +
                    " unsupported tomcat " + TestUtils.getTomcatVersion());
        }
        initTempDir();
        initTestServletClass();
        System.setProperty("catalina.base", tempDir.getAbsolutePath());
        System.setProperty("org.apache.catalina.startup.EXIT_ON_INIT_FAILURE", "true");
        Security.insertProviderAt(new BGMProvider(), 1);
        System.setProperty("jdk.tls.client.protocols", "TLSv1.3,TLSv1.2,GMTLS");
    }

    protected SSLHostConfig createSSLHostConfig(TestParameters testParameters) {
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        if (!isEmpty(testParameters.getSslProtocol())) {
            sslHostConfig.setSslProtocol(testParameters.getSslProtocol());
        }
        if (!isEmpty(testParameters.getProtocols())) {
            sslHostConfig.setProtocols(arrayToString(testParameters.getProtocols()));
        }
        if (!isEmpty(testParameters.getCiphers())) {
            sslHostConfig.setCiphers(arrayToString(testParameters.getCiphers()));
        }
        return sslHostConfig;
    }

    protected SSLHostConfigCertificate createSSLHostConfigCertificate(Cert cert,
                                                                      SSLHostConfig sslHostConfig) {
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(sslHostConfig, cert.getCertType());
        certificate.setCertificateKeyAlias(cert.getKeyAlias());
        if (Cert.FileType.KEYSTORE.equals(cert.getFileType())) {
            certificate.setCertificateKeystorePassword(cert.getPassword());
            certificate.setCertificateKeystoreType(cert.getKeyStoreType());
            certificate.setCertificateKeystoreFile(cert.getKeyStoreFile());
        } else {
            certificate.setCertificateKeyPassword(cert.getPassword());
            certificate.setCertificateFile(cert.getCertFile());
            certificate.setCertificateKeyFile(cert.getKeyFile());
            certificate.setCertificateChainFile(cert.getChainFile());
        }
        return certificate;
    }

    protected SSLHostConfigCertificate[] createSSLHostConfigCertificates(Cert[] certs,
                                                                         SSLHostConfig sslHostConfig) {
        SSLHostConfigCertificate[] sslHostConfigCertificates = new SSLHostConfigCertificate[certs.length];
        for (int i = 0; i < sslHostConfigCertificates.length; i++) {
            sslHostConfigCertificates[i] = createSSLHostConfigCertificate(
                    certs[i], sslHostConfig);
        }
        return sslHostConfigCertificates;
    }

    protected Tomcat getTomcatInstance(SSLHostConfig sslHostConfig, Cert[] certs) {
        // SSLHostConfigCertificate
        SSLHostConfigCertificate[] certificates = createSSLHostConfigCertificates(certs, sslHostConfig);
        for (SSLHostConfigCertificate certificate : certificates) {
            sslHostConfig.addCertificate(certificate);
        }

        // Connector
        Connector connector = new Connector("HTTP/1.1");
        connector.setProperty("sslImplementationName", "org.openeuler.tomcat.GMJSSEImplementation");
        connector.setProperty("SSLEnabled", "true");
        connector.setPort(0);
        connector.addSslHostConfig(sslHostConfig);

        // Tomcat
        Tomcat tomcat = new Tomcat();
        tomcat.setBaseDir(getTempDir().getAbsolutePath());
        tomcat.getService().addConnector(connector);
        tomcat.setConnector(connector);
        Context context = tomcat.addContext("", null);
        context.setLoginConfig(new LoginConfig());
        return tomcat;
    }

    protected void testConnect(TestParameters serverParameters, TestParameters clientParameters)
            throws Throwable {
        log.info(String.format("serverParameters {\n\tsslProtocol : %s\n\tprotocols : %s\n\tciphers : %s\n}",
                serverParameters.getSslProtocol(),
                Arrays.toString(serverParameters.getProtocols()),
                Arrays.toString(serverParameters.getCiphers()))
        );
        SSLHostConfig sslHostConfig = createSSLHostConfig(serverParameters);
        Tomcat tomcat = getTomcatInstance(sslHostConfig, serverParameters.getCerts());
        tomcat.addServlet("", "TestServlet", testServletClass)
                .addMapping("/test");

        HttpURLConnection connection = null;
        ByteChunk out = null;
        try {
            tomcat.start();
            int port = tomcat.getConnector().getLocalPort();
            String url = "https://localhost:" + port + "/test";
            log.info("url : " + url);
            out = new ByteChunk();
            connection = connectUrl(url, out, READ_TIMEOUT, clientParameters);
            Assert.assertTrue(out.equals(MESSAGE));
        } finally {
            if (out != null) {
                out.recycle();
            }
            if (connection != null) {
                connection.disconnect();
            }
            try {
                stopTomcat(tomcat);
            } catch (LifecycleException e) {
                log.error(e);
            }
        }
    }

    // Stop tomcat services.
    private void stopTomcat(Tomcat tomcat) throws LifecycleException {
        if (tomcat.getServer() != null
                && tomcat.getServer().getState() != LifecycleState.DESTROYED) {
            if (tomcat.getServer().getState() != LifecycleState.STOPPED) {
                tomcat.stop();
            }
            tomcat.destroy();
        }
    }

    // Set the available protocols and cipher suites of the client.
    private void addClientHttpsConfig(TestParameters clientParameters) {
        if (!isEmpty(clientParameters.getProtocols())) {
            System.setProperty("https.protocols", arrayToString(clientParameters.getProtocols()));
        }
        if (!isEmpty(clientParameters.getCiphers())) {
            System.setProperty("https.cipherSuites", arrayToString(clientParameters.getCiphers()));
        }
    }

    // Remove the available protocols and cipher suites of the client.
    private void removeClientHttpsConfig() {
        Properties properties = System.getProperties();
        properties.remove("https.protocols");
        properties.remove("https.cipherSuites");
    }

    protected HttpURLConnection connectUrl(String path, ByteChunk out,
                                           int timeout, TestParameters clientParameters) throws IOException {
        log.info(String.format("clientParameters {\n\tsslProtocol : %s\n\tprotocols : %s\n\tciphers : %s\n}",
                clientParameters.getSslProtocol(),
                Arrays.toString(clientParameters.getProtocols()),
                Arrays.toString(clientParameters.getCiphers()))
        );
        HttpURLConnection connection;
        try {
            SSLSocketFactory sslSocketFactory = getSSLSocketFactory(clientParameters);
            addClientHttpsConfig(clientParameters);
            URL url = new URL(path);
            connection = (HttpURLConnection) url.openConnection();
            if ("https".equalsIgnoreCase(url.getProtocol().toUpperCase()) && sslSocketFactory != null) {
                ((HttpsURLConnection) connection).setSSLSocketFactory(sslSocketFactory);
            }
            connection.setConnectTimeout(timeout);
            connection.connect();
            // Read response data to out
            InputStream inputStream = getInputStream(connection);
            read(inputStream, out);

            // Check cipher should
            checkCipher(connection, clientParameters);
        } finally {
            removeClientHttpsConfig();
        }

        return connection;
    }

    // The checkCipher method is called before reading the inputstream.
    private void checkCipher(HttpURLConnection connection, TestParameters clientParameters)
            throws IOException {
        if (connection.getResponseCode() < 400 && !isEmpty(clientParameters.getExpectedCipher())) {
            log.info("Use cipher suite : " + clientParameters.getExpectedCipher());
            Assert.assertEquals(clientParameters.getExpectedCipher(),
                    ((HttpsURLConnection) connection).getCipherSuite());
        }
    }

    // Read response data to ByteBuffer
    private void read(InputStream inputStream, ByteChunk out) throws IOException {
        if (inputStream != null) {
            BufferedInputStream bis = new BufferedInputStream(inputStream);
            byte[] buf = new byte[1024];
            int rd;
            while ((rd = bis.read(buf)) > 0) {
                out.append(buf, 0, rd);
            }
        }
    }

    protected SSLSocketFactory getSSLSocketFactory(TestParameters clientParameters) throws IOException {
        if (clientParameters == null) {
            clientParameters = new TestParameters.Builder().builder();
        }
        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance(clientParameters.getSslProtocol());
            sslContext.init(null, new TrustManager[]{new EmptyTrustManager()}, null);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IOException("SSLContext init failed", e);
        }
        return sslContext.getSocketFactory();
    }

    private InputStream getInputStream(HttpURLConnection connection) throws IOException {
        InputStream inputStream;
        if (connection.getResponseCode() < 400) {
            inputStream = connection.getInputStream();
        } else {
            inputStream = connection.getErrorStream();
        }
        return inputStream;
    }

    @AfterClass
    public static void afterClass() {
        removeTempDir();
    }
}
