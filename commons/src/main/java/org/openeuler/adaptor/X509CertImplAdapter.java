/*
 * Copyright (c) 2025, Huawei Technologies Co., Ltd. All rights reserved.
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

import sun.security.util.Debug;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.lang.reflect.Method;
import java.security.cert.X509Certificate;

public class X509CertImplAdapter extends AdapterBase {

    private static final String NAME = "x509";
    private static final String INFO = "info";
    private static final String SIG_ALG = "x509.algorithm";

    public X509CertImplAdapter(X509CertImpl cert) {
        proxy = cert;
    }

    private static final String IMPL_CLASS =
            "sun.security.x509.X509CertImpl";

    private static Method get;

    // JDK21
    private static Method getSigAlg;

    private static Method getInfo;

    private static Method getFingerprint;

    private static Method getFingerprintWithDebug;


    private static final Class<?> proxyClass;

    // Non-static getFingerprint methods
    // JDK 17.0.2 adds a Debug parameter to the getFingerprint function.
    // For more information refer to <a href="https://bugs.openjdk.org/browse/JDK-8270946">JDK-8270946</a>
    private static Method nonStaticGetFingerprint;

    private static Method nonStaticGetFingerprintWithDebug;

    private static final Debug certPathDebug = Debug.getInstance("certpath");

    static {
        try {
            proxyClass = Class.forName(IMPL_CLASS, true, null);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }

        try {
            init();
        } catch (InstantiationException | IllegalAccessException | NoSuchMethodException e) {
            exception = e;
        }
    }

    private static void init() throws InstantiationException,
            IllegalAccessException, NoSuchMethodException {
        if (proxyClass == null) {
            return;
        }
        try {
            get = proxyClass.getDeclaredMethod("get", String.class);
        } catch (NoSuchMethodException e) {
            getSigAlg = proxyClass.getDeclaredMethod("getSigAlg");
            getInfo = proxyClass.getDeclaredMethod("getInfo");
        }

        try {
            getFingerprint = proxyClass.getDeclaredMethod("getFingerprint", String.class, X509Certificate.class);
        } catch (NoSuchMethodException e) {
            getFingerprintWithDebug = proxyClass.getDeclaredMethod("getFingerprint", String.class, X509Certificate.class, Debug.class);
        }

        try {
            nonStaticGetFingerprint = proxyClass.getDeclaredMethod("getFingerprint", String.class);
        } catch (NoSuchMethodException e) {
            nonStaticGetFingerprintWithDebug = proxyClass.getDeclaredMethod("getFingerprint", String.class, Debug.class);
        }
    }

    /**
     * Returns the AlgorithmId.
     */
    public AlgorithmId getSigAlg() {
        ensureAvailable();
        if(get != null) {
            return (AlgorithmId) invoke(get, SIG_ALG);
        }
        return (AlgorithmId) invoke(getSigAlg);
    }

    public X509CertInfo getInfo() {
        ensureAvailable();
        if(get != null) {
            return (X509CertInfo) invoke(get, NAME + "." + INFO);
        }
        return (X509CertInfo) invoke(getInfo);
    }

    public String getFingerprint(String algorithm) {
        ensureAvailable();
        if(nonStaticGetFingerprint != null) {
            return (String) invoke(nonStaticGetFingerprint, algorithm);
        }
        return (String) invoke(nonStaticGetFingerprintWithDebug, algorithm, certPathDebug);
    }

    public static String getFingerprint(String algorithm, X509Certificate cert) {
        // ensureAvailable();
        if(getFingerprint != null) {
            return (String) invokeStatic(getFingerprint, algorithm, cert);
        }
        return (String) invokeStatic(getFingerprintWithDebug, algorithm, cert, certPathDebug);
    }
}
