/*
 * Copyright (c) 2006, 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.openeuler.sun.security.ec;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.openeuler.sun.security.ec.BGECPrivateKey;
import org.openeuler.sun.security.ec.BGECPublicKey;
import org.openeuler.util.ECUtil;
import org.openeuler.util.Util;
import sun.security.jca.JCAUtil;

/**
 * EC keypair generator.
 * Standard algorithm, minimum key length is 112 bits, maximum is 571 bits.
 *
 * This class is a modified version of the ECKeyPairGenerator class in the Sun library, designed to adapt to
 * the implementation of the SM2 algorithm.
 *
 * @see sun.security.ec.ECKeyPairGenerator
 */
public final class SM2KeyPairGenerator extends KeyPairGeneratorSpi {

    private static final int KEY_SIZE_MIN = 112; // min bits (see ecc_impl.h)
    private static final int KEY_SIZE_MAX = 571; // max bits (see ecc_impl.h)
    private static final BigInteger ONE = BigInteger.valueOf(1);

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
     * Constructs a new ECKeyPairGenerator.
     */
    public SM2KeyPairGenerator() {
        // initialize to default in case the app does not call initialize()
        initialize(SM2P256V1_KEY_SIZE, null);
    }

    // initialize the generator. See JCA doc
    @Override
    public void initialize(int keySize, SecureRandom random) {
        ECGenParameterSpec ecGenParameterSpec = ecGenParameterSpecMap.get(keySize);
        if (ecGenParameterSpec == null) {
            throw new InvalidParameterException("Unknown key size.");
        }
        try {
            initialize(ecGenParameterSpec, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    // second initialize method. See JCA doc
    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {

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

    // generate the keypair. See JCA doc
    @Override
    public KeyPair generateKeyPair() {
        if (!isInitialized) {
            initialize(SM2P256V1_KEY_SIZE, new SecureRandom());
        }

        if (random == null) {
            random = JCAUtil.getSecureRandom();
        }

        try {
            Optional<KeyPair> kp = generateKeyPairImpl(random);
            if (kp.isPresent()) {
                return kp.get();
            } else {
                throw new InvalidKeyException("key generation error");
            }
        } catch (Exception ex) {
            throw new ProviderException(ex);
        }
    }

    private Optional<KeyPair> generateKeyPairImpl(SecureRandom random)
            throws InvalidKeyException {

        ECParameterSpec ecParams = (ECParameterSpec) params;

        BigInteger n = ((ECParameterSpec) params).getOrder();
        int nBitLength = n.bitLength();
        int minWeight = nBitLength >>> 2;

        BigInteger d;
        for (;;)
        {
            d = Util.createRandomBigInteger(nBitLength, random);

            if (d.compareTo(ONE) < 0  || (d.compareTo(n) >= 0))
            {
                continue;
            }

            if (Util.getNafWeight(d) < minWeight)
            {
                continue;
            }

            break;
        }

        ECPoint genPoint = ecParams.getGenerator();
        ECPoint w = ECUtil.multiply(genPoint, d, ecParams.getCurve());

        PrivateKey privateKey = new BGECPrivateKey(d.toByteArray(), ecParams);

        PublicKey publicKey = new BGECPublicKey(w, ecParams);

        return Optional.of(new KeyPair(publicKey, privateKey));
    }
}

