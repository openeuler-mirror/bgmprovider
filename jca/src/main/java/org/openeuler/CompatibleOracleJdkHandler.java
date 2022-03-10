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

package org.openeuler;

import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Map;

public class CompatibleOracleJdkHandler {
    /**
     * @see javax.crypto.JceSecurity#verificationResults
     */
    private static Map<Provider, Object> verificationResults;

    /**
     * JceSecurity class
     */
    private static Class<?> jceSecurityClass;

    static {
        init();
    }

    @SuppressWarnings("SynchronizeOnNonFinalField")
    public static void skipJarVerify(Provider provider) {
        if (jceSecurityClass != null && verificationResults != null) {
            // The verificationResults is IdentityHashMap, not thread safe.
            synchronized (jceSecurityClass) {
                verificationResults.put(provider, Boolean.TRUE);
            }
        }
    }

    /**
     * Oracle jdk will verify whether the Provider is signed when using the Provider mechanism.
     * In order to be compatible with Oracle jdk, signature verification needs to be skipped
     * when creating a custom provider. The Provider can be identified in advance as having been
     * verified through the reflection mechanism.
     */
    @SuppressWarnings("unchecked")
    private static void init() {
        // Not oracle jdk, return directly.
        if (!isOracleJdk()) {
            return;
        }

        // Oracle jdk , identity Provider has been verified.
        try {
            jceSecurityClass = Class.forName("javax.crypto.JceSecurity");
            Field verificationResultsField = jceSecurityClass.getDeclaredField("verificationResults");
            verificationResultsField.setAccessible(true);
            Object object = verificationResultsField.get(null);
            if (object instanceof Map) {
                verificationResults = (Map<Provider, Object>) object;
            }
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            // ignore exception
        }
    }

    public static boolean isOracleJdk() {
        String vendor = AccessController.doPrivileged(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return System.getProperty("java.vendor");
            }
        });
        return vendor != null && vendor.startsWith("Oracle");
    }
}
