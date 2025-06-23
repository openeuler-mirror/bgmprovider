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
 * Please visit https://gitee.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */

package org.openeuler.adaptor;

import sun.security.x509.CertificateExtensions;
import sun.security.x509.X509CertInfo;

import java.lang.reflect.Method;

public class X509CertInfoAdapter extends AdapterBase {
    public X509CertInfoAdapter(X509CertInfo cert) {
        proxy = cert;
    }

    private static final String EXTENSIONS = "extensions";

    private static final String IMPL_CLASS =
            "sun.security.x509.X509CertInfo";

    private static Method get;

    // JDK21
    private static Method getExtensions;

    private static final Class<?> proxyClass;

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
            getExtensions = proxyClass.getDeclaredMethod("getExtensions");
        }
    }

    public CertificateExtensions getExtensions() {
        ensureAvailable();
        if(get != null) {
            return (CertificateExtensions) invoke(get, EXTENSIONS);
        }
        return (CertificateExtensions) invoke(getExtensions);
    }
}
