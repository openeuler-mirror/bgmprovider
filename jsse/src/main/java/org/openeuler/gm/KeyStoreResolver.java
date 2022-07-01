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

import org.openeuler.sun.security.pkcs12.PKCS12KeyStore;
import org.openeuler.sun.security.util.KeyStoreDelegator;

import java.security.KeyStoreSpi;

public final class KeyStoreResolver {
    private static final Class<? extends KeyStoreSpi> JKS_CLASS;
    static {
        try {
            JKS_CLASS = (Class<? extends KeyStoreSpi>) Class.forName("sun.security.provider.JavaKeyStore$JKS");
        } catch (ClassNotFoundException e) {
            throw new InternalError(e);
        }
    }

    // special PKCS12 keystore that supports PKCS12 and JKS file formats
    public static final class DualFormatPKCS12 extends KeyStoreDelegator {
        public DualFormatPKCS12() {
            super("PKCS12", PKCS12KeyStore.class, "JKS", JKS_CLASS);
        }
    }

    // special JKS that supports JKS and PKCS12 file formats
    public static final class DualFormatJKS extends KeyStoreDelegator {
        public DualFormatJKS() {
            super("JKS", JKS_CLASS, "PKCS12", PKCS12KeyStore.class);
        }
    }
}
