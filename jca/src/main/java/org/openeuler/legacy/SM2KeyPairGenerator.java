/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.legacy;

import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;

/**
 * The difference between EC and SM key pair generation is that the elliptic curve is different.
 * Refer to the key pair generation method of EC to implement the initialize(int, SecureRandom) method.
 * Delegate the implementation of the two methods of initialize(AlgorithmParameterSpec, SecureRandom)
 * and generateKeyPair to KeyPairGeneratorSpi.EC.
 *
 * @see KeyPairGeneratorSpi.EC#initialize(int, SecureRandom)
 * @see KeyPairGeneratorSpi.EC#initialize(AlgorithmParameterSpec, SecureRandom)
 * @see KeyPairGeneratorSpi.EC#generateKeyPair()
 */
public class SM2KeyPairGenerator extends java.security.KeyPairGeneratorSpi {
    // sm2p256v1 key size
    private static final int SM2P256V1_KEY_SIZE = 256;

    // wapip192v1 key size
    private static final int WAPIP192V1_KEY_SIZE = 192;

    // ECGenParameterSpec map
    private static Map<Integer, ECGenParameterSpec> ecGenParameterSpecMap;

    static {
        initECGenParameterSpecMap();
    }

    private KeyPairGeneratorSpi keyPairGenerator;

    private boolean isInitialized;

    private static void initECGenParameterSpecMap() {
        ecGenParameterSpecMap = new HashMap<>();
        ecGenParameterSpecMap.put(SM2P256V1_KEY_SIZE, new ECGenParameterSpec("sm2p256v1"));
        ecGenParameterSpecMap.put(WAPIP192V1_KEY_SIZE, new ECGenParameterSpec("wapip192v1"));
    }

    public SM2KeyPairGenerator() {
        this.keyPairGenerator = new KeyPairGeneratorSpi.EC("SM2", BouncyCastleProvider.CONFIGURATION);
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        ECGenParameterSpec ecGenParameterSpec = ecGenParameterSpecMap.get(keysize);
        if (ecGenParameterSpec == null) {
            throw new InvalidParameterException("Unknown key size.");
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
        keyPairGenerator.initialize(params, random);
        isInitialized = true;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (!isInitialized) {
            initialize(SM2P256V1_KEY_SIZE, new SecureRandom());
        }
        return keyPairGenerator.generateKeyPair();
    }
}
