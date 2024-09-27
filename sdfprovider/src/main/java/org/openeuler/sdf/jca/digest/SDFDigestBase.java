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

package org.openeuler.sdf.jca.digest;

import org.openeuler.sdf.commons.session.SDFSession;
import org.openeuler.sdf.commons.session.SDFSessionManager;

import java.security.MessageDigestSpi;

import org.openeuler.sdf.wrapper.SDFDigestNative;

abstract class SDFDigestBase extends MessageDigestSpi implements Cloneable {
    private final int digestLength;

    private final String algorithm;

    private SDFDigestContext context = null;

    private SDFSession session = null;

    SDFDigestBase(String algorithm, int digestLength) {
        this.algorithm = algorithm;
        this.digestLength = digestLength;
    }

    // init SDF Digest Context
    private void init() {
        // init session
        this.session = SDFSessionManager.getInstance().getSession();

        // init digest context
        long contextAddr = SDFDigestNative.nativeDigestInit(session.getAddress(), algorithm);
        this.context = new SDFDigestContext(session.getAddress(), contextAddr);
    }

    @Override
    protected void engineUpdate(byte input) {
        byte[] oneByte = new byte[]{input};
        engineUpdate(oneByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (len == 0 || input == null) {
            return;
        }
        if ((offset < 0) || (len < 0) || (offset > input.length - len)) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (context == null) {
            init();
        }

        try {
            SDFDigestNative.nativeDigestUpdate(session.getAddress(), context.getAddress(), input, offset, len);
        } catch (Throwable e) {
            engineReset();
            throw e;
        }
    }

    @Override
    protected byte[] engineDigest() {
        if (context == null) {
            init();
        }

        byte[] digestBytes;
        try {
            digestBytes = SDFDigestNative.nativeDigestFinal(session.getAddress(), context.getAddress(), digestLength);
        } finally {
            engineReset();
        }
        return digestBytes;
    }

    @Override
    protected void engineReset() {
        // Free SDF Digest Context
        if (context != null) {
            context.getReference().dispose();
            context = null;
        }

        // Free SDF Session
        if (session != null) {
            SDFSessionManager.getInstance().releaseSession(session);
            session = null;
        }
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        SDFDigestBase copy = (SDFDigestBase) super.clone();
        copy.session = SDFSessionManager.getInstance().getSession();
        long copyCtxAddr;
        if (copy.context != null) {
            copyCtxAddr = SDFDigestNative.nativeDigestCtxClone(
                    copy.session.getAddress(), copy.context.getAddress());
        } else {
            copyCtxAddr = SDFDigestNative.nativeDigestInit(
                    copy.session.getAddress(), algorithm);
        }
        copy.context = new SDFDigestContext(copy.session.getAddress(), copyCtxAddr);
        return copy;
    }

    public static class SM3 extends SDFDigestBase {
        public SM3() {
            super("SM3", 32);
        }
    }

    public static class MD5 extends SDFDigestBase {
        public MD5() {
            super("MD5", 16);
        }
    }

    public static class SHA1 extends SDFDigestBase {
        public SHA1() {
            super("SHA-1", 20);
        }
    }

    public static class SHA224 extends SDFDigestBase {
        public SHA224() {
            super("SHA-224", 28);
        }
    }

    public static class SHA256 extends SDFDigestBase {
        public SHA256() {
            super("SHA-256", 32);
        }
    }

    public static class SHA384 extends SDFDigestBase {
        public SHA384() {
            super("SHA-384", 48);
        }
    }

    public static class SHA512 extends SDFDigestBase {
        public SHA512() {
            super("SHA-512", 64);
        }
    }
}
