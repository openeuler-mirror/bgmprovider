/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.HashMap;
import java.util.Map;

import org.openeuler.sun.security.ec.BGECPrivateKey;
import org.openeuler.sun.security.ec.BGECPublicKey;
import org.openeuler.util.ECUtil;
import org.openeuler.util.GMUtil;
import org.openeuler.util.Util;
import sun.security.jca.JCAUtil;

/**
 * SM2 keypair generator.
 */
public final class SM2KeyPairGenerator extends KeyPairGeneratorSpi {

    // used to seed the keypair generator
    private SecureRandom random;

    // parameters specified via init, if any
    private AlgorithmParameterSpec params = null;

    // sm2p256v1 key size
    private static final int SM2P256V1_KEY_SIZE = 256;

    // wapip192v1 key size
    private static final int WAPIP192V1_KEY_SIZE = 192;

    // ECGenParameterSpec map
    private static Map<Integer, ECGenParameterSpec> ecGenParameterSpecMap;

    static {
        initECGenParameterSpecMap();
    }

    private boolean isInitialized;

    private static void initECGenParameterSpecMap() {
        ecGenParameterSpecMap = new HashMap<>();
        ecGenParameterSpecMap.put(SM2P256V1_KEY_SIZE, new ECGenParameterSpec("sm2p256v1"));
        ecGenParameterSpecMap.put(WAPIP192V1_KEY_SIZE, new ECGenParameterSpec("wapip192v1"));
    }

    /**
     * Constructs a new ECKeyPairGenerator. By default, the sm2p256v1 curve is used
     */
    public SM2KeyPairGenerator() {
        // initialize to default in case the app does not call initialize()
        initialize(SM2P256V1_KEY_SIZE, null);
    }


    @Override
    public void initialize(int keySize, SecureRandom random) {
        ECGenParameterSpec ecGenParameterSpec = ecGenParameterSpecMap.get(keySize);
        if (ecGenParameterSpec == null) {
            throw new InvalidParameterException("Unknown key size, the sm2 algorithm only supports sm2p256v1 and wapip192v1 curve");
        }
        try {
            initialize(ecGenParameterSpec, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {

        if (!GMUtil.isGMCurve(params)) {
            throw new InvalidAlgorithmParameterException(
                    "Not a GM curve : " +
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
        } else if (params instanceof ECGenParameterSpec) {
            String name = ((ECGenParameterSpec) params).getName();
            ecSpec = ECUtil.getECParameterSpec(null, name);
            if (ecSpec == null) {
                throw new InvalidAlgorithmParameterException(
                        "Unknown curve name: " + name);
            }
        } else {
            throw new InvalidAlgorithmParameterException(
                    "ECParameterSpec or ECGenParameterSpec required for SM2");
        }

        this.params = ecSpec;
        this.random = random;

        isInitialized = true;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (!isInitialized) {
            initialize(SM2P256V1_KEY_SIZE, new SecureRandom());
        }

        if (random == null) {
            random = JCAUtil.getSecureRandom();
        }

        try {
            ECParameterSpec ecParams = (ECParameterSpec) params;
            BigInteger n = ((ECParameterSpec) params).getOrder();
            int nBitLength = n.bitLength();

            BigInteger d;
            do {
                d = Util.createRandomBigInteger(nBitLength, random);
            }
            while (d.compareTo(BigInteger.ONE) < 0 || (d.compareTo(n) >= 0));

            ECPoint genPoint = ecParams.getGenerator();
            ECPoint w = ECUtil.multiply(genPoint, d, ecParams.getCurve());

            PrivateKey privateKey = new BGECPrivateKey(d, ecParams);
            PublicKey publicKey = new BGECPublicKey(w, ecParams);

            return new KeyPair(publicKey, privateKey);
        } catch (Exception ex) {
            throw new ProviderException(ex);
        }
    }
}

