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
import sun.security.x509.X509CertImpl;


import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class X509CertImplHandler {

    private static final Debug debug = Debug.getInstance("compatible");
    private static final Debug certPathDebug = Debug.getInstance("certpath");
    private static boolean useHighVersionNoStaticMethod;
    private static boolean useHighVersionStaticMethod;
    private static Method nonStatic_getFingerprint_method;
    private static Method static_getFingerprint_method;

    static {
        init();
    }

    /**
     * JDK 17.0.2 adds a Debug parameter to the two getFingerprint functions of the X509CertImpl class.
     * For more information refer to <a href="https://bugs.openjdk.org/browse/JDK-8270946">JDK-8270946</a>
     */
    private static void init() {
        initNonStaticGetFingerprintMethod();
        initStaticGetFingerprintMethod();
    }

    private static void initNonStaticGetFingerprintMethod() {
        // getFingerprint(String)
        nonStatic_getFingerprint_method = getMethod("getFingerprint", new Class[]{String.class});
        if (nonStatic_getFingerprint_method != null) {
            return;
        }

        // getFingerprint(String,Debug)
        nonStatic_getFingerprint_method = getMethod("getFingerprint", new Class[]{String.class, Debug.class});
        if (nonStatic_getFingerprint_method != null) {
            useHighVersionNoStaticMethod = true;
        }
    }

    private static void initStaticGetFingerprintMethod() {
        // getFingerprint(String,X509Certificate)
        static_getFingerprint_method = getMethod("getFingerprint", new Class[]{String.class,
                X509Certificate.class});
        if (static_getFingerprint_method != null) {
            return;
        }

        // getFingerprint(String,X509Certificate,debug)
        static_getFingerprint_method = getMethod("getFingerprint", new Class[]{String.class,
                X509Certificate.class, Debug.class});
        if (static_getFingerprint_method != null) {
            useHighVersionStaticMethod = true;
        }
    }

    private static Method getMethod(String name, Class<?>[] parameterTypes) {
        Method method = null;
        try {
            method = X509CertImpl.class.getDeclaredMethod(name, parameterTypes);
            method.setAccessible(true);
            if (debug != null) {
                String params = Arrays.toString(parameterTypes);
                params = params.substring(1, params.length() - 1);
                debug.println("Try get method (" + params + ") success");
            }
        } catch (NoSuchMethodException e) {
            if (debug != null) {
                debug.println("NoSuchMethodException :" + e.getMessage());
            }
        }
        return method;
    }

    /**
     * The non-static method getFingerprint.
     */
    public static String getFingerprint(String algorithm, X509CertImpl cert) {
        if (nonStatic_getFingerprint_method == null) {
            throw new IllegalStateException("getFingerprint(String) or getFingerprint(String,Debug) method not found");
        }
        Object[] args;
        if (useHighVersionNoStaticMethod) {
            args = new Object[]{algorithm, certPathDebug};
        } else {
            args = new Object[]{algorithm};
        }
        try {
            return (String) nonStatic_getFingerprint_method.invoke(cert, args);
        } catch (IllegalAccessException | InvocationTargetException e) {
            if (debug != null) {
                debug.println(e.getMessage());
            }
        }
        return "";
    }

    /**
     * The static method getFingerprint.
     */
    public static String getFingerprint(String algorithm, X509Certificate cert) {
        if (static_getFingerprint_method == null) {
            throw new IllegalStateException("getFingerprint(String,X509Certificate) or getFingerprint(String," +
                    "X509Certificate,Debug) method not found");
        }
        Object[] args;
        if (useHighVersionStaticMethod) {
            args = new Object[]{algorithm, cert, certPathDebug};
        } else {
            args = new Object[]{algorithm, cert};
        }
        try {
            return (String) static_getFingerprint_method.invoke(null, args);
        } catch (IllegalAccessException | InvocationTargetException e) {
            if (debug != null) {
                debug.println(e.getMessage());
            }
        }
        return "";
    }
}