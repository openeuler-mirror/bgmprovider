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

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class AdaptorTest {

    @Test
    public void adapterBaseReportsUnavailableStateAndInvokesMethods() throws Exception {
        TestAdapter adapter = new TestAdapter(new Target());
        assertEquals("ok:value", adapter.call("value"));
        assertEquals("static:value", TestAdapter.callStatic("value"));

        adapter.proxy = null;
        try {
            adapter.check();
            fail("expected AssertionError");
        } catch (AssertionError expected) {
            assertTrue(expected.getMessage().contains("proxy"));
        }

        Exception old = AdapterBase.exception;
        try {
            AdapterBase.exception = new Exception("boom");
            try {
                new TestAdapter(new Target()).check();
                fail("expected AssertionError");
            } catch (AssertionError expected) {
                assertEquals("boom", expected.getCause().getMessage());
            }
        } finally {
            AdapterBase.exception = old;
        }
    }

    @Test
    public void objectIdentifierHandlerCreatesOidFromStringAndInts() throws Exception {
        Object oid = ObjectIdentifierHandler.newObjectIdentifier("1.2.156.10197.1.301");
        assertEquals("1.2.156.10197.1.301", oid.toString());
        assertEquals("1.2.156.10197.1.301",
                ObjectIdentifierHandler.newObjectIdentifier(new int[]{1, 2, 156, 10197, 1, 301}).toString());
    }

    @Test
    public void pkcs12DefaultsReturnStableValues() {
        assertNotNull(PKCS12KeyStoreHandler.getDefaultCertPBEAlgorithm());
        assertTrue(PKCS12KeyStoreHandler.getDefaultCertPBEIterationCount() > 0);
        assertNotNull(PKCS12KeyStoreHandler.getDefaultKeyPBEAlgorithm());
        assertTrue(PKCS12KeyStoreHandler.getDefaultKeyPBEIterationCount() > 0);
        assertNotNull(PKCS12KeyStoreHandler.getDefaultMacAlgorithm());
        assertTrue(PKCS12KeyStoreHandler.getDefaultMacIterationCount() > 0);
    }

    @Test
    public void derOutputStreamAdapterDelegatesAllSupportedMethods() throws Exception {
        Class<?> derOutputStreamClass = Class.forName("sun.security.util.DerOutputStream");
        Class<?> derValueClass = Class.forName("sun.security.util.DerValue");
        Class<?> objectIdentifierClass = Class.forName("sun.security.util.ObjectIdentifier");

        Object out = derOutputStreamClass.getDeclaredConstructor().newInstance();
        Object nested = derOutputStreamClass.getDeclaredConstructor().newInstance();
        Object implicitValue = derOutputStreamClass.getDeclaredConstructor().newInstance();
        Object adapter = DerOutputStreamAdapter.class.getConstructor(derOutputStreamClass).newInstance(out);
        Object implicitAdapter = DerOutputStreamAdapter.class.getConstructor(derOutputStreamClass).newInstance(implicitValue);

        invoke(adapter, "putInteger", new Class<?>[]{int.class}, 7);
        invoke(adapter, "putInteger", new Class<?>[]{BigInteger.class}, BigInteger.TEN);
        invoke(adapter, "putOctetString", new Class<?>[]{byte[].class}, new byte[]{1, 2});
        invoke(adapter, "putNull", new Class<?>[0]);
        invoke(adapter, "putBMPString", new Class<?>[]{String.class}, "abc");
        invoke(adapter, "putOID", new Class<?>[]{objectIdentifierClass},
                ObjectIdentifierHandler.newObjectIdentifier("1.2.840.113549.1.1.1"));
        invoke(adapter, "write", new Class<?>[]{byte.class, byte[].class}, (byte) 0x04, new byte[]{1});
        invoke(adapter, "write", new Class<?>[]{byte.class, derOutputStreamClass}, (byte) 0x30, nested);
        invoke(implicitAdapter, "putOctetString", new Class<?>[]{byte[].class}, new byte[]{5, 6});
        invoke(adapter, "writeImplicit", new Class<?>[]{byte.class, derOutputStreamClass}, (byte) 0x31, implicitValue);

        Object emptySequence = java.lang.reflect.Array.newInstance(derValueClass, 0);
        Method putSequence = adapter.getClass().getMethod("putSequence", emptySequence.getClass());
        try {
            putSequence.invoke(adapter, new Object[]{emptySequence});
            fail("expected varargs forwarding failure");
        } catch (java.lang.reflect.InvocationTargetException expected) {
            assertTrue(expected.getCause() instanceof IllegalArgumentException
                    || expected.getCause() instanceof AssertionError);
        }

        byte[] encoded = (byte[]) derOutputStreamClass.getMethod("toByteArray").invoke(out);
        assertTrue(encoded.length > 0);
    }

    @Test
    public void derOutputStreamAdapterNoOpsWhenOptionalMethodsAreMissing() throws Exception {
        Class<?> derOutputStreamClass = Class.forName("sun.security.util.DerOutputStream");
        Object out = derOutputStreamClass.getDeclaredConstructor().newInstance();
        Object adapter = DerOutputStreamAdapter.class.getConstructor(derOutputStreamClass).newInstance(out);

        Map<Field, Object> oldValues = new LinkedHashMap<>();
        for (String name : Arrays.asList("write_Buf", "write_Out", "writeImplicit", "putInteger_BigInteger",
                "putInteger_Int", "putOctetString", "putNull", "putOID", "putSequence", "putBMPString")) {
            Field field = field(DerOutputStreamAdapter.class, name);
            oldValues.put(field, field.get(null));
            field.set(null, null);
        }
        try {
            invoke(adapter, "write", new Class<?>[]{byte.class, byte[].class}, (byte) 0x04, new byte[]{1});
            invoke(adapter, "write", new Class<?>[]{byte.class, derOutputStreamClass}, (byte) 0x30, out);
            invoke(adapter, "writeImplicit", new Class<?>[]{byte.class, derOutputStreamClass}, (byte) 0x31, out);
            invoke(adapter, "putInteger", new Class<?>[]{BigInteger.class}, BigInteger.ONE);
            invoke(adapter, "putInteger", new Class<?>[]{int.class}, 1);
            invoke(adapter, "putOctetString", new Class<?>[]{byte[].class}, new byte[]{1});
            invoke(adapter, "putNull", new Class<?>[0]);
            invoke(adapter, "putOID", new Class<?>[]{Class.forName("sun.security.util.ObjectIdentifier")},
                    ObjectIdentifierHandler.newObjectIdentifier("1.2.3"));
            Object emptySequence = java.lang.reflect.Array.newInstance(Class.forName("sun.security.util.DerValue"), 0);
            adapter.getClass().getMethod("putSequence", emptySequence.getClass()).invoke(adapter, new Object[]{emptySequence});
            invoke(adapter, "putBMPString", new Class<?>[]{String.class}, "abc");
        } finally {
            for (Map.Entry<Field, Object> entry : oldValues.entrySet()) {
                entry.getKey().set(null, entry.getValue());
            }
        }
    }

    @Test
    public void x509AdaptersDelegateToRealCertificateObjects() throws Exception {
        Certificate certificate = loadCertificate();
        Class<?> x509CertImplClass = Class.forName("sun.security.x509.X509CertImpl");
        Object x509 = x509CertImplClass.getMethod("toImpl", X509Certificate.class).invoke(null, certificate);
        Object adapter = X509CertImplAdapter.class.getConstructor(x509CertImplClass).newInstance(x509);

        Object sigAlg = invoke(adapter, "getSigAlg", new Class<?>[0]);
        assertNotNull(sigAlg);
        Object info = invoke(adapter, "getInfo", new Class<?>[0]);
        assertNotNull(info);
        Class<?> x509CertInfoClass = Class.forName("sun.security.x509.X509CertInfo");
        Object infoAdapter = X509CertInfoAdapter.class.getConstructor(x509CertInfoClass).newInstance(info);
        Object extensions = invoke(infoAdapter, "getExtensions", new Class<?>[0]);
        assertNotNull(extensions);
    }

    @Test
    public void x509InfoAdapterUsesGetExtensionsFallback() throws Exception {
        Certificate certificate = loadCertificate();
        Class<?> x509CertImplClass = Class.forName("sun.security.x509.X509CertImpl");
        Object x509 = x509CertImplClass.getMethod("toImpl", X509Certificate.class).invoke(null, certificate);
        Object info = invoke(X509CertImplAdapter.class.getConstructor(x509CertImplClass).newInstance(x509),
                "getInfo", new Class<?>[0]);
        X509CertInfoAdapter adapter = (X509CertInfoAdapter) Class.forName("org.openeuler.adaptor.X509CertInfoAdapter")
                .getConstructor(Class.forName("sun.security.x509.X509CertInfo")).newInstance(info);

        Field get = field(X509CertInfoAdapter.class, "get");
        Field getExtensions = field(X509CertInfoAdapter.class, "getExtensions");
        Object oldGet = get.get(null);
        Object oldGetExtensions = getExtensions.get(null);
        try {
            get.set(null, null);
            getExtensions.set(null, InfoStub.class.getDeclaredMethod("getExtensions"));
            Field proxy = field(AdapterBase.class, "proxy");
            Object oldProxy = proxy.get(adapter);
            try {
                proxy.set(adapter, new InfoStub());
                try {
                    adapter.getExtensions();
                    fail("expected cast failure");
                } catch (ClassCastException expected) {
                    assertNotNull(expected);
                }
            } finally {
                proxy.set(adapter, oldProxy);
            }
        } finally {
            get.set(null, oldGet);
            getExtensions.set(null, oldGetExtensions);
        }
    }

    @Test
    public void x509InfoAdapterUsesGenericGetWhenAvailable() throws Exception {
        Certificate certificate = loadCertificate();
        Class<?> x509CertImplClass = Class.forName("sun.security.x509.X509CertImpl");
        Object x509 = x509CertImplClass.getMethod("toImpl", X509Certificate.class).invoke(null, certificate);
        Object info = invoke(X509CertImplAdapter.class.getConstructor(x509CertImplClass).newInstance(x509),
                "getInfo", new Class<?>[0]);
        X509CertInfoAdapter realAdapter = (X509CertInfoAdapter) Class.forName("org.openeuler.adaptor.X509CertInfoAdapter")
                .getConstructor(Class.forName("sun.security.x509.X509CertInfo")).newInstance(info);
        Object extensions = realAdapter.getExtensions();
        X509CertInfoAdapter adapter = (X509CertInfoAdapter) Class.forName("org.openeuler.adaptor.X509CertInfoAdapter")
                .getConstructor(Class.forName("sun.security.x509.X509CertInfo")).newInstance(info);

        Field proxy = field(AdapterBase.class, "proxy");
        Field get = field(X509CertInfoAdapter.class, "get");
        Object oldProxy = proxy.get(adapter);
        Object oldGet = get.get(null);
        try {
            proxy.set(adapter, new GenericInfoStub(extensions));
            get.set(null, GenericInfoStub.class.getDeclaredMethod("get", String.class));
            assertEquals(extensions, adapter.getExtensions());
        } finally {
            proxy.set(adapter, oldProxy);
            get.set(null, oldGet);
        }
    }


    @Test
    public void adapterInitializationReturnsWhenProxyClassesAreUnavailable() throws Exception {
        invokeInitWithNullProxyClass(DerOutputStreamAdapter.class);
        invokeInitWithNullProxyClass(X509CertInfoAdapter.class);
        invokeInitWithNullProxyClass(X509CertImplAdapter.class);
    }

    private static void invokeInitWithNullProxyClass(Class<?> adapterClass) throws Exception {
        Field proxyClass = field(adapterClass, "proxyClass");
        Object old = proxyClass.get(null);
        Method init = adapterClass.getDeclaredMethod("init");
        init.setAccessible(true);
        try {
            setStaticObject(proxyClass, null);
            init.invoke(null);
        } finally {
            setStaticObject(proxyClass, old);
        }
    }

    private static void setStaticObject(Field field, Object value) throws Exception {
        Object unsafe = unsafe();
        Class<?> unsafeClass = unsafe.getClass();
        Object base = unsafeClass.getMethod("staticFieldBase", Field.class).invoke(unsafe, field);
        long offset = ((Long) unsafeClass.getMethod("staticFieldOffset", Field.class).invoke(unsafe, field)).longValue();
        unsafeClass.getMethod("putObject", Object.class, long.class, Object.class).invoke(unsafe, base, offset, value);
    }

    private static Object unsafe() throws Exception {
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
        theUnsafe.setAccessible(true);
        return theUnsafe.get(null);
    }

    @Test
    public void compatibleOracleJdkHandlerCanPopulateEachVerificationKeyMode() throws Exception {
        Provider provider = new Provider("CompatTest", 1.0, "test") {
            private static final long serialVersionUID = 1L;
        };
        Class<?> handler = CompatibleOracleJdkHandler.class;
        Field jceSecurityClass = field(handler, "jceSecurityClass");
        Field verificationResults = field(handler, "verificationResults");
        Field identityWrapperConstructor = field(handler, "identityWrapperConstructor");
        Field weakIdentityWrapperConstructor = field(handler, "weakIdentityWrapperConstructor");
        Field queue = field(handler, "queue");

        Object oldJceSecurityClass = jceSecurityClass.get(null);
        Object oldVerificationResults = verificationResults.get(null);
        Object oldIdentityWrapperConstructor = identityWrapperConstructor.get(null);
        Object oldWeakIdentityWrapperConstructor = weakIdentityWrapperConstructor.get(null);
        Object oldQueue = queue.get(null);
        try {
            Map<Object, Object> direct = new HashMap<>();
            jceSecurityClass.set(null, CompatibleOracleJdkHandler.class);
            verificationResults.set(null, direct);
            identityWrapperConstructor.set(null, null);
            weakIdentityWrapperConstructor.set(null, null);
            CompatibleOracleJdkHandler.skipJarVerify(provider);
            assertEquals(Boolean.TRUE, direct.get(provider));

            Class<?> identityWrapperClass = findClass("javax.crypto.JceSecurity$IdentityWrapper");
            if (identityWrapperClass != null) {
                Map<Object, Object> identity = new HashMap<>();
                verificationResults.set(null, identity);
                java.lang.reflect.Constructor<?> constructor =
                        identityWrapperClass.getDeclaredConstructor(Provider.class);
                constructor.setAccessible(true);
                identityWrapperConstructor.set(null, constructor);
                weakIdentityWrapperConstructor.set(null, null);
                CompatibleOracleJdkHandler.skipJarVerify(provider);
                assertEquals(1, identity.size());
            }
        } finally {
            jceSecurityClass.set(null, oldJceSecurityClass);
            verificationResults.set(null, oldVerificationResults);
            identityWrapperConstructor.set(null, oldIdentityWrapperConstructor);
            weakIdentityWrapperConstructor.set(null, oldWeakIdentityWrapperConstructor);
            queue.set(null, oldQueue);
        }
    }

    @Test
    public void objectIdentifierHandlerWrapsCreationFailures() throws Exception {
        Field constructor = field(ObjectIdentifierHandler.class, "objectIdentifierConstructor");
        Object old = constructor.get(null);
        try {
            constructor.set(null, String.class.getDeclaredConstructor(byte[].class));
            try {
                ObjectIdentifierHandler.newObjectIdentifier("1.2.3");
                fail("expected failure");
            } catch (IOException | IllegalArgumentException expected) {
                assertNotNull(expected);
            }
        } finally {
            constructor.set(null, old);
        }
    }

    private static Class<?> findClass(String name) throws Exception {
        try {
            return Class.forName(name);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    private static Object invoke(Object target, String name, Class<?>[] parameterTypes, Object... args) throws Exception {
        Method method = target.getClass().getMethod(name, parameterTypes);
        return method.invoke(target, args);
    }

    private static Certificate loadCertificate() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        java.io.InputStream in = Files.newInputStream(
                Paths.get("..", "jsse", "src", "test", "resources", "server-rsa.truststore"));
        try {
            keyStore.load(in, "12345678".toCharArray());
        } finally {
            in.close();
        }
        for (String alias : Arrays.asList("server-rsa", "server-ec")) {
            Certificate certificate = keyStore.getCertificate(alias);
            if (certificate instanceof X509Certificate) {
                return certificate;
            }
        }
        throw new AssertionError("No X509 certificate found in test truststore");
    }

    private static Field field(Class<?> clazz, String name) throws Exception {
        Field field = clazz.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    private static final class TestAdapter extends AdapterBase {
        private static final Method INSTANCE_METHOD;
        private static final Method STATIC_METHOD;

        static {
            try {
                INSTANCE_METHOD = Target.class.getDeclaredMethod("echo", String.class);
                STATIC_METHOD = Target.class.getDeclaredMethod("staticEcho", String.class);
            } catch (NoSuchMethodException e) {
                throw new AssertionError(e);
            }
        }

        private TestAdapter(Object proxy) {
            this.proxy = proxy;
        }

        private void check() {
            ensureAvailable();
        }

        private String call(String value) {
            ensureAvailable();
            return (String) invoke(INSTANCE_METHOD, value);
        }

        private static String callStatic(String value) {
            return (String) invokeStatic(STATIC_METHOD, value);
        }
    }

    public static final class Target {
        public String echo(String value) {
            return "ok:" + value;
        }

        public static String staticEcho(String value) {
            return "static:" + value;
        }
    }

    public static final class InfoStub {
        public Object getExtensions() {
            return new Object();
        }
    }

    public static final class GenericInfoStub {
        private final Object extensions;

        public GenericInfoStub(Object extensions) {
            this.extensions = extensions;
        }

        public Object get(String name) {
            return extensions;
        }
    }
}
