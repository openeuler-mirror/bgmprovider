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

import sun.security.util.Debug;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;

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
public class SharedSecrets {
    private static final Debug debug = Debug.getInstance("compatible");

    // Candidate SharedSecrets class
    private static final String[] candidateSharedSecretsClassNames = new String[]{
            "sun.misc.SharedSecrets",
            "jdk.internal.misc.SharedSecrets",
            "jdk.internal.access.SharedSecrets"
    };

    // Candidate JavaNetAccess class
    private static final String[] candidateJavaNetAccessClassNames = new String[]{
            "sun.misc.JavaNetAccess",
            "jdk.internal.misc.JavaNetInetAddressAccess",
            "jdk.internal.access.JavaNetInetAddressAccess"
    };

    // The getJavaNetAccess or getJavaNetInetAddressAccess method.
    private static Method getJavaNetAccessMethod;

    // The getOriginalHostName method.
    private static Method getOriginalHostNameMethod;

    static {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                init();
                return null;
            }
        });
    }

    private static void init() {
        initGetJavaNetAccessMethod();
        initGetOriginalHostNameMethod();
    }

    private static void initGetJavaNetAccessMethod() {
        Class<?> sharedSecretsClass = getSharedSecretsClass();
        if (sharedSecretsClass == null) {
            return;
        }
        String sharedSecretsClassName = sharedSecretsClass.getName().startsWith("sun.misc")
                ? "getJavaNetAccess"
                : "getJavaNetInetAddressAccess";
        try {
            getJavaNetAccessMethod = sharedSecretsClass.getDeclaredMethod(sharedSecretsClassName);
            if (debug != null) {
                debug.println("Found method " + getJavaNetAccessMethod.getName());
            }
        } catch (NoSuchMethodException e) {
            if (debug != null) {
                debug.println("NoSuchMethodException: " + e.getMessage());
            }
        }
    }

    private static void initGetOriginalHostNameMethod() {
        Class<?> javaNetAccessClass = getJavaNetAccessClass();
        if (javaNetAccessClass == null) {
            return;
        }
        try {
            getOriginalHostNameMethod = javaNetAccessClass.getDeclaredMethod("getOriginalHostName",
                    InetAddress.class);
            getOriginalHostNameMethod.setAccessible(true);
            if (debug != null) {
                debug.println("Found method " + getOriginalHostNameMethod.getName());
            }
        } catch (NoSuchMethodException e) {
            if (debug != null) {
                debug.println("NoSuchMethodException: " + e.getMessage());
            }
        }
    }

    private static Class<?> getSharedSecretsClass() {
        return getClass(candidateSharedSecretsClassNames);
    }

    private static Class<?> getJavaNetAccessClass() {
        return getClass(candidateJavaNetAccessClassNames);
    }

    private static Class<?> getClass(String[] classNames) {
        for (String className : classNames) {
            try {
                Class<?> clazz = Class.forName(className);
                if (debug != null) {
                    debug.println("Try load class " + className + " success");
                }
                return clazz;
            } catch (ClassNotFoundException e) {
                if (debug != null) {
                    debug.println("Try load class " + className + " failed");
                }
            }
        }
        if (debug != null) {
            debug.println("Can't find a suitable class from " + Arrays.toString(classNames));
        }
        return null;
    }

    private static Object getJavaNetAccess() throws NoSuchMethodException, InvocationTargetException,
            IllegalAccessException {
        if (getJavaNetAccessMethod == null) {
            throw new IllegalAccessException("getJavaNetAccess or JavaNetInetAddressAccess method not found");
        }
        return getJavaNetAccessMethod.invoke(null);
    }

    public static String getOriginalHostName(InetAddress ia) {
        if (getOriginalHostNameMethod == null) {
            throw new IllegalStateException("getOriginalHostName method not found");
        }
        try {
            Object javaNetAccess = getJavaNetAccess();
            return (String) getOriginalHostNameMethod.invoke(javaNetAccess, ia);
        } catch (InvocationTargetException | IllegalAccessException | NoSuchMethodException e) {
            throw new IllegalStateException(e);
        }
    }
}
