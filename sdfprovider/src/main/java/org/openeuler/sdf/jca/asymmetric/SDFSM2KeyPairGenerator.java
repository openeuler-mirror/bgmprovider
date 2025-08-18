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

package org.openeuler.sdf.jca.asymmetric;

import org.openeuler.sdf.commons.exception.SDFException;
import org.openeuler.sdf.commons.spec.SDFKEKInfoEntity;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECPrivateKeyImpl;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECPublicKeyImpl;
import org.openeuler.sdf.jca.commons.SDFCurveUtil;
import org.openeuler.sdf.wrapper.SDFSM2KeyPairGeneratorNative;
import sun.security.util.ECUtil;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;


/**
 * SDF SM2 keypair generator.
 */
public class SDFSM2KeyPairGenerator extends SDFKeyPairGeneratorCore {

    // parameters specified via init, if any
    private AlgorithmParameterSpec params = null;

    // sm2p256v1 key size
    private static final int SM2P256V1_KEY_SIZE = 256;

    // default curve
    private static final String SUPPORTED_CURVE_NAME = "sm2p256v1";

    /**
     * Constructs a new SDFSM2KeyPairGenerator. By default, the sm2p256v1 curve is used
     */
    public SDFSM2KeyPairGenerator() {
        super(SM2P256V1_KEY_SIZE);
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        super.initialize(keysize, random);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(SUPPORTED_CURVE_NAME);
        try {
            initialize(ecGenParameterSpec, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        super.initialize(params, random);
    }

    @Override
    protected void checkKeySize(int keysize) throws InvalidParameterException {
        if (keysize != SM2P256V1_KEY_SIZE) {
            throw new InvalidParameterException(
                    "Only support 256 bits SM2 key, the key size is" + keysize);
        }
    }

    @Override
    protected void checkParameterSpec(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (!SDFCurveUtil.isSM2Curve(params)) {
            throw new InvalidAlgorithmParameterException("Not a SM2 curve : " +
                    ((params instanceof ECGenParameterSpec) ?
                            ((ECGenParameterSpec) params).getName() : params));
        }
        ECParameterSpec ecSpec;
        if (params instanceof ECParameterSpec) {
            ECParameterSpec ecParams = (ECParameterSpec) params;
            ecSpec = ECUtil.getECParameterSpec(null, ecParams);
            if (ecSpec == null) {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported curve: " + params);
            }
        } else if (params instanceof SDFSM2GenParameterSpec) {
            String name = ((ECGenParameterSpec) params).getName();
            ecSpec = ECUtil.getECParameterSpec(null, name);
            if (ecSpec == null) {
                throw new InvalidAlgorithmParameterException(
                        "Unknown curve name: " + name);
            }
        } else if (params instanceof ECGenParameterSpec) {
            String name = ((ECGenParameterSpec) params).getName();
            ecSpec = ECUtil.getECParameterSpec(null, name);
            if (ecSpec == null) {
                throw new InvalidAlgorithmParameterException(
                        "Unknown curve name: " + name);
            }
        } else {
            throw new InvalidAlgorithmParameterException(
                    "ECParameterSpec or SDFSM2GenParameterSpec or ECGenParameterSpec required for SM2");
        }
        this.params = ecSpec;
    }

    @Override
    protected byte[][] implGenerateKeyPair(SDFKEKInfoEntity kekInfo, int keySize)
            throws SDFException {
        return SDFSM2KeyPairGeneratorNative.nativeGenerateKeyPair(
                keySize,
                kekInfo.getKekId(),
                kekInfo.getRegionId(),
                kekInfo.getCdpId(),
                kekInfo.getPin()
        );
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[][] keys = implGenerateKeyPair();

        /*
         * typedef enum SDF_ECKeyIndex {
         *     SDF_EC_PBK_X_IDX = 0,
         *     SDF_EC_PBK_Y_IDX = 1,
         *     SDF_EC_PRK_S_IDX = 2
         * } SDF_ECKeyIndex;
         */
        BigInteger wX = new BigInteger(1, keys[0]);
        BigInteger wY = new BigInteger(1, keys[1]);
        BigInteger s = new BigInteger(1, keys[2]);
        ECPoint w = new ECPoint(wX, wY);

        PrivateKey privateKey;
        PublicKey publicKey;
        ECParameterSpec ecParams = (ECParameterSpec) params;
        try {
            publicKey = new SDFECPublicKeyImpl(w, ecParams);
            privateKey = new SDFECPrivateKeyImpl(s, ecParams, isEncKey(), super.kekInfo.getPin());
        } catch (InvalidKeyException e) {
            throw new ProviderException(e);
        }
        return new KeyPair(publicKey, privateKey);
    }

}
