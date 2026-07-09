/*
 * Copyright (c) 2026, Huawei Technologies Co., Ltd. All rights reserved.
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
 * Please visit https://gitcode.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */
package org.openeuler.adaptor;

import org.junit.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class X509CertImplAdapterTest {

    @Test
    public void fingerprintOverloadsDelegateToConfiguredMethods() throws Exception {
        X509Certificate certificate = loadCertificate();
        assertNotNull(X509CertImplAdapter.getFingerprint("SHA-256", certificate));

        Class<?> x509CertImplClass = Class.forName("sun.security.x509.X509CertImpl");
        Object x509 = x509CertImplClass.getMethod("toImpl", X509Certificate.class).invoke(null, certificate);
        Object adapter = X509CertImplAdapter.class.getConstructor(x509CertImplClass).newInstance(x509);
        Field proxy = field(AdapterBase.class, "proxy");
        Field nonStaticGetFingerprint = field(X509CertImplAdapter.class, "nonStaticGetFingerprint");
        Field nonStaticGetFingerprintWithDebug = field(X509CertImplAdapter.class, "nonStaticGetFingerprintWithDebug");
        Object oldProxy = proxy.get(adapter);
        Object oldNonStaticGetFingerprint = nonStaticGetFingerprint.get(null);
        Object oldNonStaticGetFingerprintWithDebug = nonStaticGetFingerprintWithDebug.get(null);
        try {
            proxy.set(adapter, new FingerprintStub());
            nonStaticGetFingerprint.set(null, FingerprintStub.class.getDeclaredMethod("fingerprint", String.class));
            nonStaticGetFingerprintWithDebug.set(null, null);
            Method getFingerprint = adapter.getClass().getMethod("getFingerprint", String.class);
            assertEquals("fingerprint:SHA-256", getFingerprint.invoke(adapter, "SHA-256"));
        } finally {
            proxy.set(adapter, oldProxy);
            nonStaticGetFingerprint.set(null, oldNonStaticGetFingerprint);
            nonStaticGetFingerprintWithDebug.set(null, oldNonStaticGetFingerprintWithDebug);
        }
    }

    @Test
    public void fallbackMethodsAreUsedWhenGenericGettersAreUnavailable() throws Exception {
        X509Certificate certificate = loadCertificate();
        Class<?> x509CertImplClass = Class.forName("sun.security.x509.X509CertImpl");
        Object x509 = x509CertImplClass.getMethod("toImpl", X509Certificate.class).invoke(null, certificate);
        X509CertImplAdapter adapter = (X509CertImplAdapter)
                X509CertImplAdapter.class.getConstructor(x509CertImplClass).newInstance(x509);

        Field proxy = field(AdapterBase.class, "proxy");
        Field get = field(X509CertImplAdapter.class, "get");
        Field getSigAlg = field(X509CertImplAdapter.class, "getSigAlg");
        Field getInfo = field(X509CertImplAdapter.class, "getInfo");
        Field getFingerprint = field(X509CertImplAdapter.class, "getFingerprint");
        Field getFingerprintWithDebug = field(X509CertImplAdapter.class, "getFingerprintWithDebug");
        Field nonStaticGetFingerprint = field(X509CertImplAdapter.class, "nonStaticGetFingerprint");
        Field nonStaticGetFingerprintWithDebug = field(X509CertImplAdapter.class, "nonStaticGetFingerprintWithDebug");

        Object oldProxy = proxy.get(adapter);
        Object oldGet = get.get(null);
        Object oldGetSigAlg = getSigAlg.get(null);
        Object oldGetInfo = getInfo.get(null);
        Object oldGetFingerprint = getFingerprint.get(null);
        Object oldGetFingerprintWithDebug = getFingerprintWithDebug.get(null);
        Object oldNonStaticGetFingerprint = nonStaticGetFingerprint.get(null);
        Object oldNonStaticGetFingerprintWithDebug = nonStaticGetFingerprintWithDebug.get(null);
        try {
            proxy.set(adapter, new FallbackStub());
            get.set(null, null);
            getSigAlg.set(null, FallbackStub.class.getDeclaredMethod("object"));
            getInfo.set(null, FallbackStub.class.getDeclaredMethod("object"));
            try {
                adapter.getSigAlg();
                fail("expected cast failure");
            } catch (ClassCastException expected) {
                assertNotNull(expected);
            }
            try {
                adapter.getInfo();
                fail("expected cast failure");
            } catch (ClassCastException expected) {
                assertNotNull(expected);
            }

            getFingerprint.set(null, null);
            getFingerprintWithDebug.set(null,
                    FallbackStub.class.getDeclaredMethod("staticFingerprint", String.class, X509Certificate.class, Object.class));
            assertEquals("static:SHA-256", X509CertImplAdapter.getFingerprint("SHA-256", certificate));

            nonStaticGetFingerprint.set(null, null);
            nonStaticGetFingerprintWithDebug.set(null,
                    FallbackStub.class.getDeclaredMethod("fingerprint", String.class, Object.class));
            assertEquals("instance:SHA-256", adapter.getFingerprint("SHA-256"));
        } finally {
            proxy.set(adapter, oldProxy);
            get.set(null, oldGet);
            getSigAlg.set(null, oldGetSigAlg);
            getInfo.set(null, oldGetInfo);
            getFingerprint.set(null, oldGetFingerprint);
            getFingerprintWithDebug.set(null, oldGetFingerprintWithDebug);
            nonStaticGetFingerprint.set(null, oldNonStaticGetFingerprint);
            nonStaticGetFingerprintWithDebug.set(null, oldNonStaticGetFingerprintWithDebug);
        }
    }

    @Test
    public void genericGetterMethodsAreUsedWhenAvailable() throws Exception {
        X509Certificate certificate = loadCertificate();
        Class<?> x509CertImplClass = Class.forName("sun.security.x509.X509CertImpl");
        Object x509 = x509CertImplClass.getMethod("toImpl", X509Certificate.class).invoke(null, certificate);
        X509CertImplAdapter realAdapter = (X509CertImplAdapter)
                X509CertImplAdapter.class.getConstructor(x509CertImplClass).newInstance(x509);
        GenericGetStub stub = new GenericGetStub(realAdapter.getSigAlg(), realAdapter.getInfo());
        X509CertImplAdapter adapter = (X509CertImplAdapter)
                X509CertImplAdapter.class.getConstructor(x509CertImplClass).newInstance(x509);

        Field proxy = field(AdapterBase.class, "proxy");
        Field get = field(X509CertImplAdapter.class, "get");
        Field getFingerprint = field(X509CertImplAdapter.class, "getFingerprint");
        Object oldProxy = proxy.get(adapter);
        Object oldGet = get.get(null);
        Object oldGetFingerprint = getFingerprint.get(null);
        try {
            proxy.set(adapter, stub);
            get.set(null, GenericGetStub.class.getDeclaredMethod("get", String.class));
            assertEquals(stub.sigAlg, adapter.getSigAlg());
            assertEquals(stub.info, adapter.getInfo());

            getFingerprint.set(null,
                    GenericGetStub.class.getDeclaredMethod("staticFingerprint", String.class, X509Certificate.class));
            assertEquals("direct:SHA-256", X509CertImplAdapter.getFingerprint("SHA-256", certificate));
        } finally {
            proxy.set(adapter, oldProxy);
            get.set(null, oldGet);
            getFingerprint.set(null, oldGetFingerprint);
        }
    }

    private static Field field(Class<?> clazz, String name) throws Exception {
        Field field = clazz.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    private static X509Certificate loadCertificate() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        java.io.InputStream in = Files.newInputStream(
                Paths.get("..", "jsse", "src", "test", "resources", "server-rsa.truststore"));
        try {
            keyStore.load(in, "12345678".toCharArray());
        } finally {
            in.close();
        }
        Certificate certificate = keyStore.getCertificate("server-rsa");
        assertTrue(certificate instanceof X509Certificate);
        return (X509Certificate) certificate;
    }

    public static final class FingerprintStub {
        public String fingerprint(String algorithm) {
            return "fingerprint:" + algorithm;
        }
    }

    public static final class FallbackStub {
        public Object object() {
            return new Object();
        }

        public String fingerprint(String algorithm, Object debug) {
            return "instance:" + algorithm;
        }

        public static String staticFingerprint(String algorithm, X509Certificate certificate, Object debug) {
            return "static:" + algorithm;
        }
    }

    public static final class GenericGetStub {
        private final Object sigAlg;
        private final Object info;

        public GenericGetStub(Object sigAlg, Object info) {
            this.sigAlg = sigAlg;
            this.info = info;
        }

        public Object get(String name) {
            if ("x509.algorithm".equals(name)) {
                return sigAlg;
            }
            if ("x509.info".equals(name)) {
                return info;
            }
            return null;
        }

        public static String staticFingerprint(String algorithm, X509Certificate certificate) {
            return "direct:" + algorithm;
        }
    }
}
