/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.sdf.jsse;

import org.openeuler.sdf.commons.key.SDFEncryptKey;
import org.openeuler.sun.security.internal.interfaces.TlsMasterSecret;

public final class SDFGMTlsMasterSecretKey implements TlsMasterSecret, SDFEncryptKey {
    private byte[] key;
    private final int majorVersion;
    private final int minorVersion;

    // use enc key
    private boolean isEncKey = true;

    SDFGMTlsMasterSecretKey(byte[] key, int majorVersion, int minorVersion) {
        this.key = key;
        this.majorVersion = majorVersion;
        this.minorVersion = minorVersion;
    }

    SDFGMTlsMasterSecretKey(byte[] key, int majorVersion, int minorVersion, boolean isEncKey) {
        this.key = key;
        this.majorVersion = majorVersion;
        this.minorVersion = minorVersion;
        this.isEncKey = isEncKey;
    }

    public int getMajorVersion() {
        return majorVersion;
    }

    public int getMinorVersion() {
        return minorVersion;
    }

    public String getAlgorithm() {
        return "TlsMasterSecret";
    }

    public String getFormat() {
        return "RAW";
    }

    public byte[] getEncoded() {
        return key.clone();
    }

    @Override
    public boolean isEncKey() {
        return isEncKey;
    }
}