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

import sun.security.util.DerOutputStream;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.X509CertInfo;

import java.lang.reflect.Method;
import java.math.BigInteger;

public class DerOutputStreamAdapter extends AdapterBase {
    public DerOutputStreamAdapter(DerOutputStream out) {
        proxy = out;
    }

    private static final String IMPL_CLASS =
            "sun.security.util.DerOutputStream";

    private static final Class<?> proxyClass;

    private static Method putOID;

    private static Method putInteger_BigInteger;

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
            putOID = proxyClass.getDeclaredMethod("putOID", ObjectIdentifier.class);
            putInteger_BigInteger = proxyClass.getDeclaredMethod("putInteger", BigInteger.class);
        } catch (NoSuchMethodException e) {
            throw e;
        }
    }

    public void putOID(ObjectIdentifier oid) {
        ensureAvailable();
        if(putOID != null) {
            invoke(putOID, oid);
        }
    }

    public void putInteger(BigInteger var1) {
        ensureAvailable();
        if(putInteger_BigInteger != null) {
            invoke(putInteger_BigInteger, var1);
        }
    }
}
