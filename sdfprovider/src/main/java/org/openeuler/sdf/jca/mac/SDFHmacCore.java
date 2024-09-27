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

package org.openeuler.sdf.jca.mac;

import org.openeuler.sdf.commons.exception.SDFException;
import org.openeuler.sdf.commons.exception.SDFRuntimeException;
import org.openeuler.sdf.commons.session.SDFSession;
import org.openeuler.sdf.commons.session.SDFSessionManager;
import org.openeuler.sdf.wrapper.SDFHmacNative;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;

abstract class SDFHmacCore extends MacSpi implements Cloneable {
    private String digestName;
    private int macLen;
    private SDFSession session;
    private SDFHmacContext context;
    private Key key;

    public SDFHmacCore(String digestName, int macLen) {
        this.digestName = digestName;
        this.macLen = macLen;
    }

    @Override
    protected int engineGetMacLength() {
        return this.macLen;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException
                    ("HMAC does not use parameters");
        }
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Secret key expected");
        }

        this.key = key;
        try {
            init();
        } catch (SDFException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[]{input}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        // len should be more than 0
        if (len == 0 || input == null) {
            return;
        }

        try {
            init();
            SDFHmacNative.nativeHmacUpdate(session.getAddress(), context.getAddress(), input, offset, len);
        } catch (SDFException e) {
            engineReset();
            throw new SDFRuntimeException("nativeHmacUpdate failed.", e);
        }
    }

    @Override
    protected byte[] engineDoFinal() {
        byte[] result;
        try {
            init();
            result = SDFHmacNative.nativeHmacFinal(session.getAddress(), context.getAddress(), macLen);
        } catch (SDFException e) {
            throw new SDFRuntimeException("nativeHmacFinal failed.", e);
        } finally {
            engineReset();
        }
        return result;
    }

    @Override
    protected void engineReset() {
        if (context != null) {
            context.getReference().dispose();
            context = null;
        }
        if (session != null) {
            SDFSessionManager.getInstance().releaseSession(session);
            session = null;
        }
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        SDFHmacCore copy =(SDFHmacCore) super.clone();
        copy.session = SDFSessionManager.getInstance().getSession();
        long ctxAddress;
        try {
            if (context == null) {
                ctxAddress = SDFHmacNative.nativeHmacInit(copy.session.getAddress(), key.getEncoded(), digestName);
            } else {
                ctxAddress = SDFHmacNative.nativeHmacContextClone(session.getAddress(), context.getAddress());
            }
        } catch (SDFException e) {
            throw new SDFRuntimeException(e);
        }
        copy.context = new SDFHmacContext(copy.session.getAddress(), ctxAddress);
        return copy;
    }

    private void init() throws SDFException {
        if (session == null) {
            session = SDFSessionManager.getInstance().getSession();
        }
        if (context == null) {
            long hmacContextAddress = SDFHmacNative.nativeHmacInit(session.getAddress(), key.getEncoded(), digestName);
            context = new SDFHmacContext(session.getAddress(), hmacContextAddress);
        }
    }

    public static class HmacSM3 extends SDFHmacCore {
        public HmacSM3() {
            super("SM3", 32);
        }
    }

    public static class HmacMD5 extends SDFHmacCore {
        public HmacMD5() {
            super("MD5", 16);
        }
    }

    public static class HmacSHA1 extends SDFHmacCore {
        public HmacSHA1() {
            super("SHA-1", 20);
        }
    }

    public static class HmacSHA224 extends SDFHmacCore {
        public HmacSHA224() {
            super("SHA-224", 28);
        }
    }

    public static class HmacSHA256 extends SDFHmacCore {
        public HmacSHA256() {
            super("SHA-256", 32);
        }
    }

    public static class HmacSHA384 extends SDFHmacCore {
        public HmacSHA384() {
            super("SHA-384", 48);
        }
    }

    public static class HmacSHA512 extends SDFHmacCore {
        public HmacSHA512() {
            super("SHA-512", 64);
        }
    }
}
