/*
 * Copyright (c) 2026, Huawei Technologies Co., Ltd. All rights reserved.
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
 * Please visit https://gitcode.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */

package org.openeuler.sdf.jca.asymmetric;

import org.openeuler.sdf.commons.exception.SDFException;
import org.openeuler.sdf.commons.spec.SDFKEKInfoEntity;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECPrivateKeyImpl;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECPublicKeyImpl;
import org.openeuler.sdf.wrapper.SDFECCKeyPairGeneratorNative;
import sun.security.util.ECUtil;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.HashMap;
import java.util.Map;

public class SDFECKeyPairGenerator extends SDFKeyPairGeneratorCore {
    // support "secp256r1 [NIST P-256]","secp384r1 [NIST P-384]","secp521r1 [NIST P-521]"
    private static final Map<Integer, ECGenParameterSpec> supportECMap;

    // parameters specified via init, if any
    private AlgorithmParameterSpec params = null;

    static {
        supportECMap = new HashMap<>();
        supportECMap.put(256, new ECGenParameterSpec("secp256r1 [NIST P-256, X9.62 prime256v1]"));
        supportECMap.put(384, new ECGenParameterSpec("secp384r1 [NIST P-384]"));
        supportECMap.put(521, new ECGenParameterSpec("secp521r1 [NIST P-521]"));
    }

    SDFECKeyPairGenerator(int defaultKeySize) {
        super(defaultKeySize);
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        super.initialize(keysize, random);
        this.params = supportECMap.get(keysize);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        super.initialize(params, random);
    }

    @Override
    protected void checkKeySize(int keysize) throws InvalidParameterException {
        if (!supportECMap.containsKey(keysize)) {
            throw new InvalidParameterException("Key size not support " + keySize + " bits");
        }
    }

    @Override
    protected void checkParameterSpec(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        ECParameterSpec ecSpec = null;

        if (params instanceof ECParameterSpec) {
            ECParameterSpec ecParams = (ECParameterSpec) params;
            ecSpec = ECUtil.getECParameterSpec(null, ecParams);
            if (ecSpec == null) {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported curve: " + params);
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
                    "ECParameterSpec or ECGenParameterSpec required for EC");
        }
        this.params = ecSpec;
        this.keySize = ecSpec.getCurve().getField().getFieldSize();
    }

    @Override
    protected byte[][] implGenerateKeyPair(SDFKEKInfoEntity kekInfo, int keySize) throws SDFException {
        return SDFECCKeyPairGeneratorNative.nativeGenerateKeyPair(
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
