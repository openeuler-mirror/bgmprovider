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

package org.openeuler.sdf.jca.symmetric;

import org.openeuler.sdf.wrapper.SDFSymmetricCipherNative;

import javax.crypto.spec.GCMParameterSpec;

public class SDFGCMParameterSpec extends GCMParameterSpec implements SDFCipherHeadSpec {
    private byte[] tag;
    // enable cipher head
    private boolean withCipherHead;
    private byte[] cipherHeadBytes;

    public SDFGCMParameterSpec(int tLen, byte[] src) {
        super(tLen, src);
        this.tag = new byte[16];
    }

    public SDFGCMParameterSpec(int tLen, byte[] src, boolean withCipherHead) {
        super(tLen, src);
        this.tag = new byte[16];
        if (withCipherHead) {
            this.withCipherHead = true;
            this.cipherHeadBytes = SDFSymmetricCipherNative.nativeCipherHead();
        }
    }

    public byte[] getTag() {
        return tag;
    }

    public void setTag(byte[] tag) {
        this.tag = tag;
    }

    @Override
    public byte[] getCipherHeadBytes() {
        return cipherHeadBytes;
    }

    @Override
    public boolean withCipherHead() {
        return withCipherHead;
    }
}
