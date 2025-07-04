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

package org.openeuler.sdf.jca.symmetric;

import org.openeuler.sdf.commons.exception.SDFRuntimeException;
import org.openeuler.sdf.commons.spec.SDFKEKInfoEntity;
import org.openeuler.sdf.commons.spec.SDFKeyGeneratorParameterSpec;
import org.openeuler.sdf.commons.spec.SDFSecretKeySpec;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.sdf.wrapper.SDFKeyGeneratorNative;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public abstract class SDFKeyGeneratorCore extends KeyGeneratorSpi {
    private String algorithm;
    // default keysize (in number of bytes)
    private int keySize;
    private SecureRandom random;
    private boolean isHmac;
    private boolean isXts;
    private SDFKEKInfoEntity kekInfo = SDFKEKInfoEntity.getDefaultKEKInfo();

    protected SDFKeyGeneratorCore(String algorithm, int defaultKeySize) {
        this.algorithm = algorithm;
        this.keySize = defaultKeySize >> 3;
    }

    protected SDFKeyGeneratorCore(String algorithm, int defaultKeySize, boolean isHmac) {
        this(algorithm, defaultKeySize);
        this.isHmac = isHmac;
    }

    protected void initKekInfo(SDFKeyGeneratorParameterSpec parameterSpec){
        this.kekInfo = parameterSpec.getKekInfo();
    }

    protected void initIsXts(SDFKeyGeneratorParameterSpec parameterSpec) {
        if (parameterSpec instanceof SDFXTSParameterSpec) {
            SDFXTSParameterSpec spec = (SDFXTSParameterSpec) parameterSpec;
            this.isXts = spec.isXts();
        }
    }

    @Override
    protected void engineInit(SecureRandom random) {
        this.random = random;
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        checkKey(keysize);
        this.keySize = keysize >> 3;
        engineInit(random);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof SDFKeyGeneratorParameterSpec) {
            SDFKeyGeneratorParameterSpec parameterSpec = (SDFKeyGeneratorParameterSpec) params;
            initKekInfo(parameterSpec);
            initIsXts(parameterSpec);
            engineInit(parameterSpec.getKeySize(), random);
        } else {
            throw new InvalidAlgorithmParameterException("Only support SDFKeyGeneratorParameterSpec");
        }
    }

    protected abstract void checkKey(int keysize);

    @Override
    protected SecretKey engineGenerateKey() {
        if (kekInfo == null){
            byte[] key = new byte[keySize];
            if (random == null) {
                random = SDFProvider.getRandom();
            }
            random.nextBytes(key);
            return new SDFSecretKeySpec(key, algorithm);
        }
        // Generate encrypted key
        byte[] encKey;
        try {
            encKey = SDFKeyGeneratorNative.nativeGenerateSecretKey(
                    kekInfo.getKekId(),
                    kekInfo.getRegionId(),
                    kekInfo.getCdpId(),
                    kekInfo.getPin(),
                    algorithm,
                    keySize << 3,
                    isHmac, isXts);
        } catch (Exception e) {
            throw new SDFRuntimeException("engineGenerateKey failed.", e);
        }
        return new SDFSecretKeySpec(encKey, algorithm, true);
    }
}
