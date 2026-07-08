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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class PKCS12KeyStoreHandlerTest {

    @Test
    public void constructorCreatesInstance() {
        assertNotNull(new PKCS12KeyStoreHandler());
    }

    @Test
    public void defaultsAreReturnedWhenPkcs12ClassOrFieldsAreUnavailable() throws Exception {
        Field pkcs12KeyStoreClass = PKCS12KeyStoreHandler.class.getDeclaredField("pkcs12KeyStoreClass");
        pkcs12KeyStoreClass.setAccessible(true);
        Field debug = PKCS12KeyStoreHandler.class.getDeclaredField("debug");
        debug.setAccessible(true);
        Object old = pkcs12KeyStoreClass.get(null);
        Object oldDebug = debug.get(null);
        try {
            pkcs12KeyStoreClass.set(null, null);
            assertEquals("PBEWithSHA1AndRC2_40", PKCS12KeyStoreHandler.getDefaultCertPBEAlgorithm());

            pkcs12KeyStoreClass.set(null, NoPkcs12Defaults.class);
            assertEquals("PBEWithSHA1AndRC2_40", PKCS12KeyStoreHandler.getDefaultCertPBEAlgorithm());
            assertEquals(Integer.valueOf(50000),
                    Integer.valueOf(PKCS12KeyStoreHandler.getDefaultCertPBEIterationCount()));
            assertEquals("PBEWithSHA1AndDESede", PKCS12KeyStoreHandler.getDefaultKeyPBEAlgorithm());
            assertEquals(Integer.valueOf(50000),
                    Integer.valueOf(PKCS12KeyStoreHandler.getDefaultKeyPBEIterationCount()));
            assertEquals("HmacPBESHA1", PKCS12KeyStoreHandler.getDefaultMacAlgorithm());
            assertEquals(Integer.valueOf(100000),
                    Integer.valueOf(PKCS12KeyStoreHandler.getDefaultMacIterationCount()));

            setStaticObject(debug, Class.forName("sun.security.util.Debug").getDeclaredConstructor().newInstance());
            assertEquals("PBEWithSHA1AndRC2_40", PKCS12KeyStoreHandler.getDefaultCertPBEAlgorithm());
        } finally {
            setStaticObject(debug, oldDebug);
            pkcs12KeyStoreClass.set(null, old);
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

    private static class NoPkcs12Defaults {
    }
}
