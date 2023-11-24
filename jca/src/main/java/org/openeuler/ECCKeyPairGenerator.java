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

import org.openeuler.sun.security.ec.BGECPrivateKey;
import org.openeuler.sun.security.ec.BGECPublicKey;
import org.openeuler.util.GMUtil;
import sun.security.ec.ECKeyPairGenerator;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

public class ECCKeyPairGenerator extends java.security.KeyPairGeneratorSpi {

    // used to seed the keypair generator
    private SecureRandom random;

    // parameters specified via init, if any
    private AlgorithmParameterSpec params = null;

    private KeyPairGeneratorSpi engine = new ECKeyPairGenerator();

    private KeyPairGeneratorSpi sm2Engine = new SM2KeyPairGenerator();

    private boolean isInitialized = false;

    private boolean isGMCurve = false;

    public ECCKeyPairGenerator() {
        initialize(256, null);
    }

    /**
     * Initializes the key pair generator for a certain keysize, using
     * the default parameter set.
     *
     * @param keysize the keysize. This is an
     *                algorithm-specific metric, such as modulus length, specified in
     *                number of bits.
     * @param random  the source of randomness for this generator.
     * @throws InvalidParameterException if the {@code keysize} is not
     *                                   supported by this KeyPairGeneratorSpi object.
     */
    @Override
    public void initialize(int keysize, SecureRandom random) {
        engine.initialize(keysize, random);
        isInitialized = true;
    }

    // second initialize method. See JCA doc
    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        isGMCurve = GMUtil.isGMCurve(params);
        if (isGMCurve) {
            sm2Engine.initialize(params, random);
        } else {
            engine.initialize(params, random);
        }
        isInitialized = true;
    }


    /**
     * Generates a key pair. Unless an initialization method is called
     * using a KeyPairGenerator interface, algorithm-specific defaults
     * will be used. This will generate a new key pair every time it
     * is called.
     *
     * @return the newly generated {@code KeyPair}
     */
    @Override
    public KeyPair generateKeyPair() {
        if (!isInitialized) {
            initialize(256, new SecureRandom());
        }
        if (isGMCurve) {
            return sm2Engine.generateKeyPair();
        }
        KeyPair keyPair = engine.generateKeyPair();

        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        ECParameterSpec ecParams = publicKey.getParams();
        try {
            PrivateKey bgPrivateKey = new BGECPrivateKey(privateKey.getS(), ecParams);
            PublicKey bgPublicKey = new BGECPublicKey(publicKey.getW(), ecParams);
            return new KeyPair(bgPublicKey, bgPrivateKey);
        } catch (InvalidKeyException e) {
            throw new ProviderException(e);
        }
    }
}
