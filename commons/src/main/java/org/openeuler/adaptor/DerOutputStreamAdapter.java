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
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.X509CertInfo;

import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;

public class DerOutputStreamAdapter extends AdapterBase {
    public DerOutputStreamAdapter(DerOutputStream out) {
        proxy = out;
    }

    private static final String IMPL_CLASS =
            "sun.security.util.DerOutputStream";

    private static final Class<?> proxyClass;

    private static Method write_Buf;

    private static Method write_Out;

    private static Method writeImplicit;

    private static Method putInteger_BigInteger;

    private static Method putInteger_Int;

    private static Method putOctetString;

    private static Method putNull;

    private static Method putOID;

    private static Method putSequence;

    private static Method putBMPString;

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
            write_Buf = proxyClass.getDeclaredMethod("write", byte.class, byte[].class);
            write_Out = proxyClass.getDeclaredMethod("write", byte.class, DerOutputStream.class);
            writeImplicit = proxyClass.getDeclaredMethod("writeImplicit", byte.class, DerOutputStream.class);
            putInteger_BigInteger = proxyClass.getDeclaredMethod("putInteger", BigInteger.class);
            putInteger_Int = proxyClass.getDeclaredMethod("putInteger", int.class);
            putOctetString = proxyClass.getDeclaredMethod("putOctetString", byte[].class);
            putNull = proxyClass.getDeclaredMethod("putNull");
            putOID = proxyClass.getDeclaredMethod("putOID", ObjectIdentifier.class);
            putSequence = proxyClass.getDeclaredMethod("putSequence", DerValue[].class);
            putBMPString = proxyClass.getDeclaredMethod("putBMPString", String.class);
        } catch (NoSuchMethodException e) {
            throw e;
        }
    }

    public void write(byte tag, byte[] buf) {
        ensureAvailable();
        if(write_Buf != null) {
            invoke(write_Buf, tag, buf);
        }
    }

    public void write(byte tag, DerOutputStream out) {
        ensureAvailable();
        if(write_Out != null) {
            invoke(write_Out, tag, out);
        }
    }

    public void writeImplicit(byte tag, DerOutputStream value) {
        ensureAvailable();
        if(writeImplicit != null) {
            invoke(writeImplicit, tag, value);
        }
    }

    public void putInteger(BigInteger i) {
        ensureAvailable();
        if(putInteger_BigInteger != null) {
            invoke(putInteger_BigInteger, i);
        }
    }

    public void putInteger(int i) {
        ensureAvailable();
        if(putInteger_Int != null) {
            invoke(putInteger_Int, i);
        }
    }

    public void putOctetString(byte[] bits) {
        ensureAvailable();
        if(putOctetString != null) {
            invoke(putOctetString, bits);
        }
    }

    public void putNull() {
        ensureAvailable();
        if(putNull != null) {
            invoke(putNull);
        }
    }

    public void putOID(ObjectIdentifier oid) {
        ensureAvailable();
        if(putOID != null) {
            invoke(putOID, oid);
        }
    }

    public void putSequence(DerValue[] seq) {
        ensureAvailable();
        if(putSequence != null) {
            invoke(putSequence, seq);
        }
    }

    public void putBMPString(String s) {
        ensureAvailable();
        if(putBMPString != null) {
            invoke(putBMPString, s);
        }
    }
}
