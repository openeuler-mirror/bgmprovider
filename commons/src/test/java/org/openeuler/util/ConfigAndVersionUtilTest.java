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
package org.openeuler.util;

import org.junit.Test;
import org.openeuler.org.bouncycastle.SM2ParameterSpec;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.AlgorithmParameterSpec;

import static org.junit.Assert.*;

public class ConfigAndVersionUtilTest {

    @Test
    public void configEnablePrefersSystemPropertyThenDefault() {
        String key = "org.openeuler.test.config";
        String old = System.getProperty(key);
        try {
            System.clearProperty(key);
            assertTrue(ConfigUtil.enable(key));
            assertFalse(ConfigUtil.enable(key, "false"));

            System.setProperty(key, "true");
            assertTrue(ConfigUtil.enable(key, "false"));
            System.setProperty(key, "false");
            assertFalse(ConfigUtil.enable(key, "true"));
        } finally {
            restoreProperty(key, old);
        }
    }

    @Test
    public void configInitializationLoadsMissingExistingAndInvalidPaths() throws Exception {
        String old = System.getProperty("bgmprovider.conf");
        try {
            Path missing = Paths.get("target", "missing-bgmprovider.conf");
            System.setProperty("bgmprovider.conf", missing.toString());
            loadConfigUtilAndEnable("not.present");

            Path config = Files.createTempFile("bgmprovider", ".conf");
            Files.write(config, "from.file=true\n".getBytes("UTF-8"));
            System.setProperty("bgmprovider.conf", config.toString());
            assertEquals(Boolean.TRUE, loadConfigUtilAndEnable("from.file"));

            System.setProperty("bgmprovider.conf", Paths.get("target").toString());
            loadConfigUtilAndEnable("not.present");
        } finally {
            restoreProperty("bgmprovider.conf", old);
        }
    }

    @Test
    public void configDebugAndSecurityManagerBranchesAreCovered() throws Exception {
        Field debug = ConfigUtil.class.getDeclaredField("debug");
        debug.setAccessible(true);
        Object oldDebug = debug.get(null);
        SecurityManager oldSecurityManager = System.getSecurityManager();
        String oldConfig = System.getProperty("bgmprovider.conf");
        try {
            setStaticObject(debug, Class.forName("sun.security.util.Debug").getDeclaredConstructor().newInstance());
            System.setProperty("bgmprovider.conf", Paths.get("target").toString());
            invokeConfigInit();

            if (setSecurityManagerField(new NoOpSecurityManager())) {
                invokeConfigInit();
            }

            System.clearProperty("org.openeuler.config.debug.test");
            assertTrue(ConfigUtil.enable("org.openeuler.config.debug.test"));
        } finally {
            setSecurityManagerField(oldSecurityManager);
            setStaticObject(debug, oldDebug);
            restoreProperty("bgmprovider.conf", oldConfig);
        }
    }

    private static void invokeConfigInit() throws Exception {
        Method initConfig = ConfigUtil.class.getDeclaredMethod("initConfig");
        initConfig.setAccessible(true);
        initConfig.invoke(null);
    }

    private static boolean setSecurityManagerField(SecurityManager securityManager) throws Exception {
        Field field;
        try {
            field = System.class.getDeclaredField("security");
        } catch (NoSuchFieldException e) {
            return false;
        }
        setStaticObject(field, securityManager);
        return true;
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

    private static final class NoOpSecurityManager extends SecurityManager {
        @Override
        public void checkPermission(java.security.Permission perm) {
        }

        @Override
        public void checkPermission(java.security.Permission perm, Object context) {
        }
    }

    private static Object loadConfigUtilAndEnable(String key) throws Exception {
        URLClassLoader loader = new URLClassLoader(new URL[]{Paths.get("target", "classes").toUri().toURL()}, null);
        try {
            Class<?> configUtil = Class.forName("org.openeuler.util.ConfigUtil", true, loader);
            return configUtil.getDeclaredMethod("enable", String.class).invoke(null, key);
        } finally {
            loader.close();
        }
    }

    @Test
    public void sm2UtilCreatesParameterSpecForConfiguredJceMode() {
        byte[] id = new byte[]{1, 2};
        AlgorithmParameterSpec spec = SM2Util.createSM2ParameterSpec(id);
        if (ConfigUtil.useLegacyJCE()) {
            assertTrue(spec == null || spec.getClass().getName().equals("org.bouncycastle.jcajce.spec.SM2ParameterSpec"));
            return;
        }

        assertTrue(spec instanceof SM2ParameterSpec);
        id[0] = 9;
        assertArrayEquals(new byte[]{9, 2}, ((SM2ParameterSpec) spec).getId());
    }

    @Test
    public void javaVersionPublicPredicatesMatchCurrentVersion() throws Exception {
        Object current = JavaVersionUtil.current();
        Method toString = current.getClass().getDeclaredMethod("toString");
        toString.setAccessible(true);
        assertNotNull(toString.invoke(current));

        int major = getIntField(current, "majorVersion");
        assertEquals(major == 8, JavaVersionUtil.isJava8());
        assertEquals(major == 11, JavaVersionUtil.isJava11());
        assertEquals(major == 17, JavaVersionUtil.isJava17());
        assertEquals(major >= 11, JavaVersionUtil.isJava11PlusSpec());
        assertEquals(major >= 12, JavaVersionUtil.isJava12PlusSpec());
        assertEquals(major >= 17, JavaVersionUtil.isJava17PlusSpec());
        Method higherThanOrEquals = JavaVersionUtil.class.getDeclaredMethod("higherThanOrEquals", current.getClass());
        Method lowerThanOrEquals = JavaVersionUtil.class.getDeclaredMethod("lowerThanOrEquals", current.getClass());
        Method equals = JavaVersionUtil.class.getDeclaredMethod("equals", current.getClass());
        assertEquals(Boolean.TRUE, higherThanOrEquals.invoke(null, newVersion(8, 0)));
        assertEquals(Boolean.FALSE, higherThanOrEquals.invoke(null, newVersion(255, 0)));
        assertEquals(Boolean.TRUE, lowerThanOrEquals.invoke(null, newVersion(255, 0)));
        assertEquals(Boolean.FALSE, lowerThanOrEquals.invoke(null, newVersion(8, 0)));
        assertEquals(Boolean.TRUE, equals.invoke(null, current));
        assertEquals(Boolean.FALSE, equals.invoke(null, newVersion(1, 0)));
    }

    @Test
    public void javaVersionPrivateHelpersParseCompareAndFormatVersions() throws Exception {
        Class<?> holderClass = Class.forName("org.openeuler.util.JavaVersionUtil$JavaVersionHolder");
        Method getVersions = holderClass.getDeclaredMethod("getVersions", String.class);
        getVersions.setAccessible(true);
        assertArrayEquals(new int[]{17, 0, 15}, (int[]) getVersions.invoke(null, "17.0.15"));

        Object java8 = newVersion(8, 302);
        Object java11 = newVersion(11, 0);
        Object java11Patch = newFullVersion(new int[]{11, 0, 2, 1});
        Method compare = java8.getClass().getDeclaredMethod("compare", java8.getClass());
        compare.setAccessible(true);
        assertEquals(-1, compare.invoke(java8, java11));
        assertEquals(1, compare.invoke(java11, java8));
        assertEquals(0, compare.invoke(java8, newVersion(8, 302)));

        Method toString = java8.getClass().getDeclaredMethod("toString");
        toString.setAccessible(true);
        assertEquals("1.8.0_302", toString.invoke(java8));
        assertEquals("11.0.2.1", toString.invoke(java11Patch));
        assertEquals("11.0.2", toString.invoke(newFullVersion(new int[]{11, 0, 2, 0})));
    }

    private static Object newVersion(int major, int minor) throws Exception {
        Class<?> versionClass = Class.forName("org.openeuler.util.JavaVersionUtil$JavaVersion");
        Constructor<?> constructor = versionClass.getDeclaredConstructor(int.class, int.class);
        constructor.setAccessible(true);
        return constructor.newInstance(major, minor);
    }

    private static Object newFullVersion(int[] versions) throws Exception {
        Class<?> versionClass = Class.forName("org.openeuler.util.JavaVersionUtil$JavaVersion");
        Constructor<?> constructor = versionClass.getDeclaredConstructor(int.class, int.class, int[].class);
        constructor.setAccessible(true);
        return constructor.newInstance(versions[0], versions[2], versions);
    }

    private static int getIntField(Object object, String fieldName) throws Exception {
        java.lang.reflect.Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.getInt(object);
    }

    private static void restoreProperty(String key, String old) {
        if (old == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, old);
        }
    }
}
