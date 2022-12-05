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

package org.openeuler;


import sun.security.util.Debug;
import sun.security.x509.X509CertImpl;


import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.X509Certificate;

public class X509CertImplHandler {

    private static final Debug debug = Debug.getInstance("certpath");

    private static Method nonStatic_getFingerprint_method;
    private static Method static_getFingerprint_method;

    static {
        initX509CertImpl();
    }

    /**
     * JDK 17.0.2 adds a Debug parameter to the two getFingerprint functions of the X509CertImpl class.
     * For more information refer to <a href="https://bugs.openjdk.org/browse/JDK-8270946">JDK-8270946</a>
     */
    private static void initX509CertImpl() {
        try {
            Class<?> clazz = Class.forName("sun.security.x509.X509CertImpl");
            if (JavaVersion.higherThanOrEquals(JavaVersion.V_17_0_2)) { // 17.0.2+
                nonStatic_getFingerprint_method = clazz.getDeclaredMethod("getFingerprint", String.class, Debug.class);
                static_getFingerprint_method = clazz.getDeclaredMethod("getFingerprint", String.class,
                        X509Certificate.class, Debug.class);
            } else {
                nonStatic_getFingerprint_method = clazz.getDeclaredMethod("getFingerprint", String.class);
                static_getFingerprint_method = clazz.getDeclaredMethod("getFingerprint", String.class,
                        X509Certificate.class);
            }
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            // ignore
        }
    }

    public static String getFingerprint(String algorithm, X509CertImpl cert) {
        Object[] args;
        if (JavaVersion.higherThanOrEquals(JavaVersion.V_17_0_2)) {
            args = new Object[]{algorithm, debug};
        } else {
            args = new Object[]{algorithm};
        }
        try {
            return (String) nonStatic_getFingerprint_method.invoke(cert, args);
        } catch (IllegalAccessException | InvocationTargetException e) {
            //ignore
        }
        return "";
    }

    public static String getFingerprint(String algorithm, X509Certificate cert) {
        Object[] args;
        if (JavaVersion.higherThanOrEquals(JavaVersion.V_17_0_2)) {
            args = new Object[]{algorithm, cert, debug};
        } else {
            args = new Object[]{algorithm, cert};
        }
        try {
            return (String) static_getFingerprint_method.invoke(null, args);
        } catch (IllegalAccessException | InvocationTargetException e) {
            //ignore
        }
        return "";
    }
}