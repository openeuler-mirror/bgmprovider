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

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.lang.reflect.Method;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JavaVersionUtilTest {

    @Test
    public void constructorAndHolderOracleVendorPredicateWork() throws Exception {
        assertNotNull(new JavaVersionUtil());

        Class<?> holderClass = Class.forName("org.openeuler.util.JavaVersionUtil$JavaVersionHolder");
        Method isOracleJdk = holderClass.getDeclaredMethod("isOracleJdk");
        isOracleJdk.setAccessible(true);
        assertEquals(Boolean.valueOf(JavaVersionUtil.isOracleJdk()), isOracleJdk.invoke(null));
    }

    @Test
    public void isolatedClassLoadersCoverVersionParsingBranches() throws Exception {
        assertIsolatedVersion("1.8.0_302", "Oracle Corporation", "1.8.0_302", true,
                true, false, false, false, false, false);
        assertIsolatedVersion("11.0.31", "Eclipse Adoptium", "11.0.31", false,
                false, true, false, false, false, true);
        assertIsolatedVersion("17.0.15-internal", "Eclipse Adoptium", "17.0.15", false,
                false, false, true, true, true, true);
        assertIsolatedVersion("21.0.11", "Oracle Corporation", "21.0.11", true,
                false, false, false, true, true, true);
        assertIsolatedVersion(null, null, "1.8.0_302", false,
                true, false, false, false, false, false);
    }

    private static void assertIsolatedVersion(String version, String vendor, String expected, boolean oracle,
                                             boolean java8, boolean java11, boolean java17,
                                             boolean java17Plus, boolean java12Plus,
                                             boolean java11Plus) throws Exception {
        String oldVersion = System.getProperty("java.version");
        String oldVendor = System.getProperty("java.vendor");
        try {
            setOrClear("java.version", version);
            setOrClear("java.vendor", vendor);
            URLClassLoader loader = new URLClassLoader(new URL[]{Paths.get("target", "classes").toUri().toURL()}, null);
            try {
                Class<?> util = Class.forName("org.openeuler.util.JavaVersionUtil", true, loader);
                Object current = util.getDeclaredMethod("current").invoke(null);
                assertEquals(expected, current.toString());
                assertEquals(Boolean.valueOf(oracle), util.getDeclaredMethod("isOracleJdk").invoke(null));
                Class<?> holder = Class.forName("org.openeuler.util.JavaVersionUtil$JavaVersionHolder", true, loader);
                Method holderOracleJdk = holder.getDeclaredMethod("isOracleJdk");
                holderOracleJdk.setAccessible(true);
                assertEquals(Boolean.valueOf(oracle), holderOracleJdk.invoke(null));
                assertEquals(Boolean.valueOf(java8), util.getDeclaredMethod("isJava8").invoke(null));
                assertEquals(Boolean.valueOf(java11), util.getDeclaredMethod("isJava11").invoke(null));
                assertEquals(Boolean.valueOf(java17), util.getDeclaredMethod("isJava17").invoke(null));
                assertEquals(Boolean.valueOf(java17Plus), util.getDeclaredMethod("isJava17PlusSpec").invoke(null));
                assertEquals(Boolean.valueOf(java12Plus), util.getDeclaredMethod("isJava12PlusSpec").invoke(null));
                assertEquals(Boolean.valueOf(java11Plus), util.getDeclaredMethod("isJava11PlusSpec").invoke(null));
            } finally {
                loader.close();
            }
        } finally {
            setOrClear("java.version", oldVersion);
            setOrClear("java.vendor", oldVendor);
        }
    }

    private static void setOrClear(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }
}
