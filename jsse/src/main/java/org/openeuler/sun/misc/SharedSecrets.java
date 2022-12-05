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

package org.openeuler.sun.misc;

import org.openeuler.JavaVersion;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class SharedSecrets {
    // The getJavaNetAccess or getJavaNetInetAddressAccess method.
    private static Method getJavaNetAccessMethod;

    // The getOriginalHostName method.
    private static Method getOriginalHostNameMethod;

    // Init method exception.
    private static Exception exception;

    static {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                init();
                return null;
            }
        });
    }

    /**
     * Different versions of jdk's SharedSecrets class are in different packages.
     * jdk8 package name - sun.misc
     * jdk11 package name - jdk.internal.misc
     * jdk17 package name - jdk.internal.access
     * <p>
     * The JavaNetAccess class in jdk8 does not exist in jdk11, but JavaNetInetAddressAccess is used instead.
     * The package name of the class is also different, and the method of obtaining the instance of the class
     * is also different.
     * jdk8 package name - sun.misc
     * jdk11 package name - jdk.internal.misc
     * jdk17 package name - jdk.internal.access
     */
    private static void init() {
        // The SharedSecrets class.
        Class<?> sharedSecretsClass;

        // The JavaNetAccess or JavaNetInetAddressAccess class.
        Class<?> javaNetAccessClass;
        try {
            if (JavaVersion.isJava8()) {
                sharedSecretsClass = Class.forName("sun.misc.SharedSecrets");
                javaNetAccessClass = Class.forName("sun.misc.JavaNetAccess");
                getJavaNetAccessMethod = sharedSecretsClass.getDeclaredMethod("getJavaNetAccess");
            } else if (JavaVersion.isJava11PlusSpec()) {
                String pkg = "jdk.internal.misc";
                // oracle jdk or version >= 12.0.19
                if (JavaVersion.isOracleJdk() || JavaVersion.higherThanOrEquals(JavaVersion.V_12_0_19)) {
                    pkg = "jdk.internal.access";
                }
                sharedSecretsClass = Class.forName(pkg + ".SharedSecrets");
                javaNetAccessClass = Class.forName(pkg + ".JavaNetInetAddressAccess");
                getJavaNetAccessMethod = sharedSecretsClass.getDeclaredMethod("getJavaNetInetAddressAccess");
            } else {
                throw new IllegalArgumentException("Unsupported jdk " + JavaVersion.current());
            }
            getOriginalHostNameMethod = javaNetAccessClass.getDeclaredMethod(
                    "getOriginalHostName", InetAddress.class);
            getOriginalHostNameMethod.setAccessible(true);
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            exception = e;
        }
    }

    private static Object getJavaNetAccess() throws InvocationTargetException, IllegalAccessException {
        return getJavaNetAccessMethod.invoke(null);
    }

    public static String getOriginalHostName(InetAddress ia) {
        if (exception != null) {
            throw new AssertionError(exception);
        }

        try {
            Object javaNetAccess = getJavaNetAccess();
            return (String) getOriginalHostNameMethod.invoke(javaNetAccess, ia);
        } catch (InvocationTargetException | IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }
}
