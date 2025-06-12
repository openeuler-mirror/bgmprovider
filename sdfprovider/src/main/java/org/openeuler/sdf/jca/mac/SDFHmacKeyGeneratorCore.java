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

import org.openeuler.sdf.jca.symmetric.SDFKeyGeneratorCore;
import org.openeuler.sdf.commons.spec.SDFKeyGeneratorParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

abstract class SDFHmacKeyGeneratorCore extends SDFKeyGeneratorCore {

    private static final int MIN_KEY_SIZE = 0;

    private static final int MAX_KEY_SIZE = 1151;

    protected SDFHmacKeyGeneratorCore(String algorithm, int defaultKeySize) {
        super(algorithm, defaultKeySize, true);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof SDFKeyGeneratorParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only support SDFKeyGeneratorParameterSpec");
        }
        SDFKeyGeneratorParameterSpec parameterSpec = (SDFKeyGeneratorParameterSpec) params;
        initKekInfo(parameterSpec);
        engineInit(parameterSpec.getKeySize(), random);
    }

    @Override
    protected void checkKey(int keysize) {
        if (keysize < MIN_KEY_SIZE || keysize > MAX_KEY_SIZE) {
            throw new InvalidParameterException(
                    "Key length must be in [" + MIN_KEY_SIZE + "," + MAX_KEY_SIZE + "] bits");
        }
    }

    public static final class HmacSM3 extends SDFHmacKeyGeneratorCore {
        public HmacSM3() {
            super("HmacSM3", 256);
        }
    }

    public static class HmacMD5 extends SDFHmacKeyGeneratorCore {
        public HmacMD5() {
            super("HmacMD5", 128);
        }
    }

    public static class HmacSHA1 extends SDFHmacKeyGeneratorCore {
        public HmacSHA1() {
            super("HmacSHA1", 160);
        }
    }

    public static class HmacSHA224 extends SDFHmacKeyGeneratorCore {
        public HmacSHA224() {
            super("HmacSHA224", 224);
        }
    }

    public static class HmacSHA256 extends SDFHmacKeyGeneratorCore {
        public HmacSHA256() {
            super("HmacSHA256", 256);
        }
    }

    public static class HmacSHA384 extends SDFHmacKeyGeneratorCore {
        public HmacSHA384() {
            super("HmacSHA384", 384);
        }
    }

    public static class HmacSHA512 extends SDFHmacKeyGeneratorCore {
        public HmacSHA512() {
            super("HmacSHA512", 512);
        }
    }
}
