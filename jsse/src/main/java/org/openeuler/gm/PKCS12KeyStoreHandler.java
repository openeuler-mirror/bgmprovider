/*
 * Copyright (c) 2022, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.gm;

import sun.security.util.Debug;

import java.lang.reflect.Field;

public class PKCS12KeyStoreHandler {
    private static final Debug debug = Debug.getInstance("compatible");
    private static final String LEGACY_CERT_PBE_ALGORITHM = "PBEWithSHA1AndRC2_40";
    private static final String LEGACY_KEY_PBE_ALGORITHM = "PBEWithSHA1AndDESede";
    private static final String LEGACY_MAC_ALGORITHM = "HmacPBESHA1";
    private static final int LEGACY_PBE_ITERATION_COUNT = 50000;
    private static final int LEGACY_MAC_ITERATION_COUNT = 100000;

    private static Class<?> pkcs12KeyStoreClass;

    static {
        init();
    }

    private static void init() {
        try {
            pkcs12KeyStoreClass = Class.forName("sun.security.pkcs12.PKCS12KeyStore");
        } catch (ClassNotFoundException e) {
            if (debug != null) {
                debug.println("The sun.security.pkcs12.PKCS12KeyStore class does not exist");
            }
        }
    }

    public static String getDefaultCertPBEAlgorithm() {
        return getFieldValue("DEFAULT_CERT_PBE_ALGORITHM", LEGACY_CERT_PBE_ALGORITHM);
    }

    public static int getDefaultCertPBEIterationCount() {
        return getFieldValue("DEFAULT_CERT_PBE_ITERATION_COUNT", LEGACY_PBE_ITERATION_COUNT);
    }

    public static String getDefaultKeyPBEAlgorithm() {
        return getFieldValue("DEFAULT_KEY_PBE_ALGORITHM", LEGACY_KEY_PBE_ALGORITHM);
    }

    public static int getDefaultKeyPBEIterationCount() {
        return getFieldValue("DEFAULT_KEY_PBE_ITERATION_COUNT", LEGACY_PBE_ITERATION_COUNT);
    }

    public static String getDefaultMacAlgorithm() {
        return getFieldValue("DEFAULT_MAC_ALGORITHM", LEGACY_MAC_ALGORITHM);
    }

    public static int getDefaultMacIterationCount() {
        return getFieldValue("DEFAULT_MAC_ITERATION_COUNT", LEGACY_MAC_ITERATION_COUNT);
    }

    private static <T> T getFieldValue(String fieldName, T defaultValue) {
        if (pkcs12KeyStoreClass == null) {
            return defaultValue;
        }

        Field field;
        try {
            field = pkcs12KeyStoreClass.getDeclaredField(fieldName);
            field.setAccessible(true);
        } catch (NoSuchFieldException e) {
            if (debug != null) {
                debug.println("Field " + fieldName + " does not exist");
            }
            return defaultValue;
        }

        try {
            return (T) field.get(null);
        } catch (IllegalAccessException e) {
            if (debug != null) {
                debug.println(e.getMessage());
            }
        }
        return defaultValue;
    }
}
