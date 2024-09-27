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

package org.openeuler.sdf.jsse;

import org.openeuler.sdf.commons.exception.SDFRuntimeException;
import org.openeuler.sdf.commons.key.SDFEncryptKey;
import org.openeuler.sdf.commons.session.SDFSession;
import org.openeuler.sdf.commons.session.SDFSessionManager;
import org.openeuler.sdf.commons.spec.SDFSecretKeySpec;
import org.openeuler.sdf.jca.commons.SDFUtil;
import org.openeuler.sdf.jsse.commons.SDFKeyExchangeUtil;
import org.openeuler.sdf.wrapper.SDFSM2KeyAgreementNative;
import org.openeuler.spec.SM2KeyExchangeParameterSpec;
import org.openeuler.sdf.wrapper.entity.SDFECCrefPublicKey;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * SM2 KeyAgreement
 */
public class SDFSM2KeyAgreement extends KeyAgreementSpi {
    // local id
    private byte[] localId;
    // local private key
    private ECPrivateKey localPrivateKey;
    // local public key
    private ECPublicKey localPublicKey;
    // local temp private key (local random)
    private ECPrivateKey localTempPrivateKey;
    // local temp public key
    private ECPublicKey localTempPublicKey;

    // peer Id
    private byte[] peerId;
    // peer public key
    private ECPublicKey peerPublicKey;
    // peer temp public key (R point , R = r*G)
    private ECPublicKey peerTempPublicKey;


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
        if((key instanceof SDFEncryptKey) && !((SDFEncryptKey) key).isEncKey()) {
            throw new InvalidKeyException("EncryptKey expected. SDFProvider supports only encrypted localPrivateKey.");
        }
        this.localPrivateKey = (ECPrivateKey) key;

        SM2KeyExchangeParameterSpec parameterSpec = checkParams(params);
        this.localId = parameterSpec.getLocalId();

        // generate localPublicKey
        if (parameterSpec.getLocalPublicKey() == null) {
            this.localPublicKey = SDFKeyExchangeUtil.generatePublicKey(this.localPrivateKey);
        } else {
            this.localPublicKey = parameterSpec.getLocalPublicKey();
        }
        this.localTempPrivateKey = parameterSpec.getLocalTempPrivateKey();
        // check localTempPrivateKey
        if((localTempPrivateKey instanceof SDFEncryptKey) && !((SDFEncryptKey) localTempPrivateKey).isEncKey()) {
            throw new InvalidKeyException("EncryptKey expected. SDFProvider supports only encrypted localTempPrivateKey.");
        }
        this.localTempPublicKey = parameterSpec.getLocalTempPublicKey();

        this.peerId = parameterSpec.getPeerId();
        this.peerTempPublicKey = parameterSpec.getPeerTempPublicKey();

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
            throw new InvalidAlgorithmParameterException("The local public key must be ECPublicKey");
        }
        if (parameterSpec.getLocalId() == null) {
            throw new InvalidAlgorithmParameterException("The localId cannot be null");
        }
        if (parameterSpec.getLocalTempPrivateKey() == null) {
            throw new InvalidAlgorithmParameterException("The local temp private key cannot be null");
        }
        if (parameterSpec.getPeerId() == null) {
            throw new InvalidAlgorithmParameterException("The peerId cannot be null");
        }
        if (parameterSpec.getPeerTempPublicKey() == null) {
            throw new InvalidAlgorithmParameterException("The peer temp public key cannot be null");
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
        SDFSession session = SDFSessionManager.getInstance().getSession();
        try {
            byte[] localCipherPriKey = SDFUtil.asUnsignedByteArray(localPrivateKey);
            byte[] tmpCipherPriKey = SDFUtil.asUnsignedByteArray(localTempPrivateKey);
            SDFECCrefPublicKey localPublicKey = new SDFECCrefPublicKey(this.localPublicKey);
            SDFECCrefPublicKey localTempPublicKey = new SDFECCrefPublicKey(this.localTempPublicKey);
            SDFECCrefPublicKey peerPublicKey = new SDFECCrefPublicKey(this.peerPublicKey);
            SDFECCrefPublicKey peerTempPublicKey = new SDFECCrefPublicKey(this.peerTempPublicKey);

            sharedSecretKey = SDFSM2KeyAgreementNative.generateSharedSecret(session.getAddress(), localId, localCipherPriKey, localPublicKey,
                    tmpCipherPriKey, localTempPublicKey,
                    peerId, peerPublicKey, peerTempPublicKey, secretLen << 3, useClientMode);
        } catch (Exception e) {
            throw new SDFRuntimeException(e);
        } finally {
            SDFSessionManager.getInstance().releaseSession(session);
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
        return new SDFSecretKeySpec(engineGenerateSecret(), algorithm, true);
    }
}
