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

package org.openeuler.sm2;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * SM2 KeyAgreement
 */
public class SM2KeyAgreement extends KeyAgreementSpi {
    // local public key
    private ECPublicKey localPublicKey;

    // local private key
    private ECPrivateKey localPrivateKey;

    // local id
    private byte[] localId;

    // local random
    private BigInteger localRandom;

    // peer public key
    private ECPublicKey peerPublicKey;

    // peer R point , R = r*G
    private byte[] peerRBytes;

    // peer Id
    private byte[] peerId;

    // length of the secret to be derived
    private int secretLen;

    // if use client mode
    private boolean useClientMode;

    @Override
    protected void engineInit(Key key, SecureRandom random)
            throws InvalidKeyException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof ECPrivateKey)) {
            throw new InvalidKeyException("ECPrivateKey expected");
        }
        this.localPrivateKey = (ECPrivateKey) key;

        SM2KeyExchangeParameterSpec parameterSpec = checkParams(params);

        // generate localPublicKey
        if (parameterSpec.getLocalPublicKey() == null) {
            this.localPublicKey = SM2KeyExchangeUtil.generatePublicKey(this.localPrivateKey);
        } else {
            this.localPublicKey = (ECPublicKey) parameterSpec.getLocalPublicKey();
        }

        this.localId = parameterSpec.getLocalId();
        this.localRandom = parameterSpec.getLocalRandom();

        this.peerId = parameterSpec.getPeerId();
        this.peerRBytes = parameterSpec.getPeerRBytes();

        this.secretLen = parameterSpec.getSecretLen();
        this.useClientMode = parameterSpec.isUseClientMode();
    }

    private SM2KeyExchangeParameterSpec checkParams(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof SM2KeyExchangeParameterSpec)) {
            throw new InvalidAlgorithmParameterException("SM2KeyExchangeParameterSpec parameters expected");
        }
        SM2KeyExchangeParameterSpec parameterSpec = (SM2KeyExchangeParameterSpec) params;
        if (parameterSpec.getLocalPublicKey() != null &
                !(parameterSpec.getLocalPublicKey() instanceof ECPublicKey)) {
            throw new InvalidAlgorithmParameterException("The localPublicKey must be ECPublicKey");
        }
        if (parameterSpec.getLocalId() == null) {
            throw new InvalidAlgorithmParameterException("The localId cannot be null");
        }
        if (parameterSpec.getLocalRandom() == null) {
            throw new InvalidAlgorithmParameterException("The localRandom cannot be null");
        }
        if (parameterSpec.getPeerId() == null) {
            throw new InvalidAlgorithmParameterException("The peerId cannot be null");
        }
        if (parameterSpec.getPeerRBytes() == null) {
            throw new InvalidAlgorithmParameterException("The peerRBytes cannot be null");
        }
        if (parameterSpec.getSecretLen() < 0) {
            throw new InvalidAlgorithmParameterException("The keyLength cannot be less than 0");
        }
        return parameterSpec;
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (this.localPrivateKey == null) {
            throw new IllegalStateException("Not initialized");
        }
        if (!(key instanceof ECPublicKey)) {
            throw new InvalidKeyException
                    ("Key must be a PublicKey with algorithm EC");
        }
        this.peerPublicKey = (ECPublicKey) key;
        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (this.localPrivateKey == null || this.peerPublicKey == null) {
            throw new IllegalStateException("Not initialized");
        }
        byte[] sharedSecretKey;
        try {
            sharedSecretKey = SM2KeyExchangeUtil.generateSharedSecret(localPublicKey, localPrivateKey,
                    localRandom, localId, peerPublicKey, peerRBytes, peerId, secretLen, useClientMode);
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e.getMessage());
        }
        return sharedSecretKey;
    }


    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        if (offset + secretLen > sharedSecret.length) {
            throw new ShortBufferException("Need " + secretLen
                    + " bytes, only " + (sharedSecret.length - offset)
                    + " available");
        }
        byte[] secret = engineGenerateSecret();
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException {
        if (algorithm == null) {
            throw new NoSuchAlgorithmException("Algorithm must not be null");
        }
        return new SecretKeySpec(engineGenerateSecret(), algorithm);
    }
}
