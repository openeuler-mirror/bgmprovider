/*
 * Copyright (c) 2003, 2024, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.sdf.jca.asymmetric;

import org.openeuler.sdf.commons.exception.SDFException;
import org.openeuler.sdf.commons.exception.SDFRuntimeException;
import org.openeuler.sdf.commons.session.SDFSession;
import org.openeuler.sdf.commons.session.SDFSessionManager;
import org.openeuler.sdf.wrapper.SDFRSAKeyPairGeneratorNative;
import sun.security.rsa.RSAUtil.KeyType;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import static sun.security.util.SecurityProviderConstants.DEF_RSA_KEY_SIZE;

abstract class SDFRSAKeyPairGenerator extends KeyPairGeneratorSpi {
    private int keySize;

    private final KeyType type;

    private AlgorithmParameterSpec params;

    SDFRSAKeyPairGenerator(KeyType type, int defKeySize) {
        this.type = type;
        initialize(defKeySize, null);
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        try {
            initialize(new RSAKeyGenParameterSpec(keysize,
                    RSAKeyGenParameterSpec.F4), random);
        } catch (InvalidAlgorithmParameterException iape) {
            throw new InvalidParameterException(iape.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof RSAKeyGenParameterSpec)) {
            throw new InvalidAlgorithmParameterException
                    ("Params must be instance of RSAKeyGenParameterSpec");
        }

        RSAKeyGenParameterSpec rsaSpec = (RSAKeyGenParameterSpec) params;
        int tmpKeySize = rsaSpec.getKeysize();
        BigInteger tmpPublicExponent = rsaSpec.getPublicExponent();
        this.params = rsaSpec.getKeyParams();

        // Only supports publicExponent of size RSAKeyGenParameterSpec.F4
        if (!RSAKeyGenParameterSpec.F4.equals(tmpPublicExponent)) {
            throw new InvalidAlgorithmParameterException
                    ("Public exponent must be 65537");
        }
        if (tmpPublicExponent.bitLength() > tmpKeySize) {
            throw new InvalidAlgorithmParameterException
                    ("Public exponent must be smaller than key size");
        }

        checkKeySize(tmpKeySize);

        this.keySize = tmpKeySize;
    }

    private static void checkKeySize(int keySize) throws InvalidAlgorithmParameterException {
        if (keySize < 1024 || keySize > 4096 || keySize % 1024 != 0) {
            throw new InvalidAlgorithmParameterException("Only support keySize 1024,2048,3072,4096");
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        SDFSession session = SDFSessionManager.getInstance().getSession();
        byte[][] nativeKeyParams;
        try {
            nativeKeyParams = SDFRSAKeyPairGeneratorNative.nativeGenerateKeyPair(
                    session.getAddress(),
                    null, null, null, null, keySize
            );
        } catch (SDFException e) {
            throw new SDFRuntimeException(e);
        } finally {
            SDFSessionManager.getInstance().releaseSession(session);
        }

        // check key parameters
        checkNativeKeyParams(nativeKeyParams);

        PublicKey publicKey;
        PrivateKey privateKey;
        try {
            publicKey = SDFRSACore.translateToRSAPublicKey(type, params, nativeKeyParams);
            privateKey = SDFRSACore.translateToRSAPrivateKey(type, params, nativeKeyParams);
        } catch (InvalidKeyException ex) {
            throw new ProviderException(ex);
        }
        return new KeyPair(publicKey, privateKey);
    }

    private static void checkNativeKeyParams(byte[][] nativeKeyParams) {
        if (nativeKeyParams == null) {
            throw new SDFRuntimeException("nativeKeyParams should not be  null");
        }
        if (nativeKeyParams.length != SDFRSAKeyParamIndex.PRIME_COEFF.getIndex() + 1) {
            throw new SDFRuntimeException("Invalid length " + nativeKeyParams.length + "," +
                    "the length of nativeKeyParams should be 8");
        }
        for (int i = 0; i < nativeKeyParams.length; i++) {
            if (nativeKeyParams[i] == null) {
                throw new SDFRuntimeException("nativeKeyParams[" + i + "] should not be null");
            }
        }
    }

    public static final class Legacy extends SDFRSAKeyPairGenerator {
        public Legacy() {
            super(KeyType.RSA, DEF_RSA_KEY_SIZE);
        }
    }
}
