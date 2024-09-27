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

import org.openeuler.sdf.commons.session.SDFSession;
import org.openeuler.sdf.commons.session.SDFSessionManager;
import org.openeuler.sdf.commons.spec.SDFKEKInfoEntity;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECPrivateKeyImpl;
import org.openeuler.sdf.jca.commons.SDFUtil;
import org.openeuler.sdf.jca.commons.SDFSM2CipherMode;
import org.openeuler.sdf.wrapper.entity.SDFECCCipherEntity;
import org.openeuler.sdf.wrapper.entity.SDFECCrefPublicKey;
import org.openeuler.spec.ECCPremasterSecretKeySpec;
import org.openeuler.sun.security.internal.spec.TlsECCKeyAgreementParameterSpec;
import org.openeuler.sdf.wrapper.SDFECCKeyAgreementNative;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import static org.openeuler.sdf.commons.constant.SDFConstant.ENC_FIXED_KEY_SIZE;

public class SDFECCKeyAgreement extends KeyAgreementSpi {

    private SDFKEKInfoEntity kekInfo = SDFKEKInfoEntity.getDefaultKEKInfo();

    private final static String MSG = "SDFECCKeyAgreement must be "
            + "initialized using a TlsECCKeyAgreementParameterSpec";

    // default mode
    private SDFSM2CipherMode mode = SDFSM2CipherMode.C1C3C2;

    private TlsECCKeyAgreementParameterSpec spec;

    private SecureRandom random;

    // creat need publicKey.
    private ECPublicKey publicKey;

    // decode need privateKey. privateKey must be encrypted.
    private SDFECPrivateKeyImpl privateKey;

    private static final int ECC_PREMASTER_KEY_LEN = 48;

    @Override
    protected void engineInit(Key key, SecureRandom random) {
        throw new UnsupportedOperationException(MSG);
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(params instanceof TlsECCKeyAgreementParameterSpec)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        if (key instanceof ECPublicKey) {
            this.publicKey = (ECPublicKey) key;
        } else if (key instanceof SDFECPrivateKeyImpl) {
            this.privateKey = (SDFECPrivateKeyImpl) key;
        } else {
            throw new InvalidKeyException("SDFECCKeyAgreement only support ECPublicKey or SDFECPrivateKeyImpl.");
        }
        this.spec = (TlsECCKeyAgreementParameterSpec) params;
        this.random = random;
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws IllegalStateException {
        throw new UnsupportedOperationException("SDFECCKeyAgreement not support engineDoPhase.");
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        throw new UnsupportedOperationException("SDFECCKeyAgreement.engineGenerateSecret only support the return SecretKey.");
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws IllegalStateException {
        throw new UnsupportedOperationException("SDFECCKeyAgreement.engineGenerateSecret only support the return SecretKey.");
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm) throws IllegalStateException {
        if (spec == null) {
            throw new IllegalStateException(
                    "SDFECCKeyAgreement.TlsECCKeyAgreementParameterSpec must be initialized");
        }
        if (spec.isClient()) {
            return generatePreMasterSecret();
        }
        return decryptSecret();
    }

    private ECCPremasterSecretKeySpec generatePreMasterSecret() {
        if (kekInfo == null) {
            throw new InvalidParameterException("In sdf mode, kekInfo cannot be empty.");
        }
        if (publicKey == null) {
            throw new IllegalStateException(
                    "publicKey must be initialized");
        }
        byte[] preMasterKey = new byte[ENC_FIXED_KEY_SIZE];;
        byte[] encryptedKey;
        SDFSession session = SDFSessionManager.getInstance().getSession();

        try {
            SDFECCrefPublicKey publicKey = new SDFECCrefPublicKey(this.publicKey);
            // generate preMasterKey(encrypted by kek) and encryptedKey (preMasterKey encrypted by public)
            SDFECCCipherEntity entity = SDFECCKeyAgreementNative.generateECCPreMasterKey(
                    session.getAddress(), kekInfo.getKekId(), kekInfo.getRegionId(),
                    kekInfo.getCdpId(), kekInfo.getPIN(), publicKey, preMasterKey, ECC_PREMASTER_KEY_LEN,
                    spec.getClientVersion());
            encryptedKey = SDFUtil.encodeECCCipher(SDFSM2CipherMode.C1C3C2, entity);
        } catch (IOException e) {
            throw new RuntimeException("encodeECCCipher failed", e);
        } finally {
            SDFSessionManager.getInstance().releaseSession(session);
        }
        return new ECCPremasterSecretKeySpec(preMasterKey,"TlsEccPremasterSecret", encryptedKey);
    }

    private ECCPremasterSecretKeySpec decryptSecret() {
        if (privateKey == null) {
            throw new IllegalStateException(
                    "privateKey must be initialized");
        }
        if (spec.getEncryptedSecret() == null) {
            throw new IllegalStateException(
                    "TlsECCKeyAgreementParameterSpec.encryptedSecret must be initialized");
        }

        SDFSession session = SDFSessionManager.getInstance().getSession();
        // preMasterKey - SDF preMasterKey Encrypted by KEK;
        // encryptedKey - preMasterKey Encrypted by publicKey
        byte[] preMasterKey = null;
        byte[] encryptedKey = spec.getEncryptedSecret();
        try {
            int curveLength = this.privateKey.getParams().getCurve().getField().getFieldSize();
            preMasterKey = SDFECCKeyAgreementNative.decodeECCPreMasterKey(session.getAddress(),
                    SDFUtil.asUnsignedByteArray(privateKey),
                    SDFUtil.decodeECCCipher(mode, spec.getEncryptedSecret(), curveLength),
                    curveLength);
        } catch (Exception e) {
            throw new RuntimeException("decodeECCPreMasterKey failed", e);
        } finally {
            SDFSessionManager.getInstance().releaseSession(session);
        }
        return new ECCPremasterSecretKeySpec(preMasterKey,"TlsEccPremasterSecret", encryptedKey);
    }
}
